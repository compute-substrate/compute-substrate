use anyhow::{Result, bail};
use futures::StreamExt;
use futures::{AsyncReadExt, AsyncWriteExt};
use libp2p::{
    PeerId, identity,
    swarm::{Swarm, SwarmEvent, NetworkBehaviour},
    Multiaddr,
    gossipsub::{self, IdentTopic, MessageAuthenticity, ValidationMode},
    request_response::{self, ProtocolSupport},
    noise, yamux, tcp, Transport,
    core::upgrade,
};
use std::{collections::{HashSet, HashMap}, sync::Arc, time::Duration};

use crate::{
    state::db::{Stores, get_tip, set_tip, k_block},
    chain::index::{get_hidx, header_hash, index_header},
    chain::reorg::maybe_reorg_to,
    state::utxo::validate_and_apply_block,
    state::app::current_epoch,
    types::{Hash32, Block, BlockHeader},
};

use super::proto::*;

const SYNC_PROTOCOL: &str = SYNC_PROTO;

#[derive(Clone)]
pub struct NetConfig {
    pub listen: Multiaddr,
    pub bootnodes: Vec<Multiaddr>,
    pub genesis_hash: Hash32,
    pub is_bootnode: bool,
}

#[derive(Clone)]
pub struct NetHandle {
    pub peer_id: PeerId,
}

#[derive(Debug)]
pub enum OutEvent {
    Gossipsub(gossipsub::Event),
    Rr(request_response::Event<SyncRequest, SyncResponse>),
}

impl From<gossipsub::Event> for OutEvent {
    fn from(e: gossipsub::Event) -> Self { OutEvent::Gossipsub(e) }
}

impl From<request_response::Event<SyncRequest, SyncResponse>> for OutEvent {
    fn from(e: request_response::Event<SyncRequest, SyncResponse>) -> Self { OutEvent::Rr(e) }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "OutEvent")]
pub struct Behaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub rr: request_response::Behaviour<SyncCodec>,
}

#[derive(Clone, Default)]
pub struct SyncCodec;

#[async_trait::async_trait]
impl request_response::Codec for SyncCodec {
    type Protocol = &'static str;
    type Request = SyncRequest;
    type Response = SyncResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> std::io::Result<Self::Request>
    where
        T: futures::prelude::AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
        let req: SyncRequest = bincode::deserialize(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(req)
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> std::io::Result<Self::Response>
    where
        T: futures::prelude::AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
        let resp: SyncResponse = bincode::deserialize(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(resp)
    }

    async fn write_request<T>(&mut self, _: &Self::Protocol, io: &mut T, req: Self::Request) -> std::io::Result<()>
    where
        T: futures::prelude::AsyncWrite + Unpin + Send,
    {
        let bytes = bincode::serialize(&req)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        io.write_all(&bytes).await?;
        io.close().await?;
        Ok(())
    }

    async fn write_response<T>(&mut self, _: &Self::Protocol, io: &mut T, resp: Self::Response) -> std::io::Result<()>
    where
        T: futures::prelude::AsyncWrite + Unpin + Send,
    {
        let bytes = bincode::serialize(&resp)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        io.write_all(&bytes).await?;
        io.close().await?;
        Ok(())
    }
}

pub async fn run_p2p(db: Arc<Stores>, cfg: NetConfig) -> Result<NetHandle> {
    let local_key = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(local_key.public());
    println!("[p2p] peer_id: {peer_id}");

    let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::Config::new(&local_key).unwrap())
        .multiplex(yamux::Config::default())
        .boxed();

    let gs_cfg = gossipsub::ConfigBuilder::default()
        .validation_mode(ValidationMode::Permissive)
        .heartbeat_interval(Duration::from_secs(1))
        .message_id_fn(|m: &gossipsub::Message| {
            use blake3::Hasher;
            let mut h = Hasher::new();
            h.update(&m.data);
            gossipsub::MessageId::from(h.finalize().to_hex().to_string())
        })
        .build()
        .unwrap();

    let mut gossipsub = gossipsub::Behaviour::new(
        MessageAuthenticity::Signed(local_key.clone()),
        gs_cfg
    ).map_err(|e| anyhow::anyhow!(e))?;

    let topic_hdr = IdentTopic::new(TOPIC_HDR);
    let topic_tx  = IdentTopic::new(TOPIC_TX);
    gossipsub.subscribe(&topic_hdr)?;
    gossipsub.subscribe(&topic_tx)?;

    let rr_cfg = request_response::Config::default();
    let protocols = std::iter::once((SYNC_PROTOCOL, ProtocolSupport::Full));
    let rr = request_response::Behaviour::<SyncCodec>::new(protocols, rr_cfg);

    let behaviour = Behaviour { gossipsub, rr };

    let mut swarm = Swarm::new(
        transport,
        behaviour,
        peer_id,
        libp2p::swarm::Config::with_tokio_executor(),
    );

    swarm.listen_on(cfg.listen.clone())?;
    println!("[p2p] listening on {}", cfg.listen);

    for a in &cfg.bootnodes {
        println!("[p2p] dialing bootnode {a}");
        let _ = swarm.dial(a.clone());
    }

    let mut seen_blocks: HashSet<Hash32> = HashSet::new();
    let mut pending_block_requests: HashMap<Hash32, request_response::OutboundRequestId> = HashMap::new();

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                println!("[p2p] NewListenAddr: {}", address);
            }

            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                println!("[p2p] connected: {peer_id}");
                let rid = swarm.behaviour_mut().rr.send_request(&peer_id, SyncRequest::GetTip);
                println!("[sync] requested tip ({rid:?})");
            }

            SwarmEvent::Behaviour(event) => {
                if let Some((src, data, topic)) = handle_gossipsub_event(&event) {
                    if topic == TOPIC_HDR {
                        let gh: GossipHeader = bincode::deserialize(&data)?;

                        let _ = cfg.genesis_hash;
                        let _ = gh.hash;

                        if !seen_blocks.contains(&gh.hash) {
                            seen_blocks.insert(gh.hash);

                            if db.blocks.get(k_block(&gh.hash))?.is_none() {
                                if let Some(src_peer) = src {
                                    let rid = swarm.behaviour_mut().rr.send_request(
                                        &src_peer,
                                        SyncRequest::GetBlock { hash: gh.hash }
                                    );
                                    pending_block_requests.insert(gh.hash, rid);
                                    println!("[sync] requested block {} from {}", hex32(&gh.hash), src_peer);
                                }
                            }
                        }
                    } else if topic == TOPIC_TX {
                        let _gt: GossipTx = bincode::deserialize(&data)?;
                    }
                }

                if let Some(rr_ev) = as_rr_event(event) {
                    use request_response::{Event, Message};

                    match rr_ev {
                        Event::Message { peer, message } => match message {
                            Message::Request { request, channel, .. } => {
                                let resp = handle_request(db.clone(), request).await;
                                let resp = resp.unwrap_or_else(|e| SyncResponse::Err{ msg: e.to_string() });
if let Err(_e) = swarm.behaviour_mut().rr.send_response(channel, resp) {
    // peer likely disconnected or channel closed; ignore
}

                            }
                            Message::Response { request_id, response } => {
                                match response {
                                    SyncResponse::Tip { hash, height, chainwork } => {
                                        println!("[sync] peer tip {} height {} work {}", hex32(&hash), height, chainwork);

                                        let local_tip = get_tip(&db)?.unwrap_or([0u8;32]);
                                        let from = if local_tip == [0u8;32] {
                                            0
                                        } else {
                                            get_hidx(&db, &local_tip)?.map(|h| h.height + 1).unwrap_or(0)
                                        };

                                        let rid = swarm.behaviour_mut().rr.send_request(
                                            &peer,
                                            SyncRequest::GetHeaders { from_height: from, max: 2000 }
                                        );
                                        println!("[sync] requested headers from {from} ({rid:?})");
                                    }

                                    SyncResponse::Headers { headers } => {
                                        println!("[sync] received {} headers", headers.len());

                                        for (hdr, h, _height, _work) in headers {
                                            if hdr.prev == [0u8;32] {
                                                let _ = index_header(&db, &hdr, None)?;
                                            } else {
                                                let parent = get_hidx(&db, &hdr.prev)?;
                                                if let Some(p) = parent {
                                                    let _ = index_header(&db, &hdr, Some(&p))?;
                                                } else {
                                                    continue;
                                                }
                                            }

                                            if db.blocks.get(k_block(&h))?.is_none() && !pending_block_requests.contains_key(&h) {
                                                let rid = swarm.behaviour_mut().rr.send_request(&peer, SyncRequest::GetBlock { hash: h });
                                                pending_block_requests.insert(h, rid);
                                            }
                                        }
                                    }

                                    SyncResponse::Block { block } => {
                                        let bh = header_hash(&block.header);

                                        if db.blocks.get(k_block(&bh))?.is_none() {
                                            db.blocks.insert(k_block(&bh), bincode::serialize(&block)?)?;
                                        }

                                        if block.header.prev == [0u8;32] {
                                            let _ = index_header(&db, &block.header, None)?;
                                        } else if let Some(p) = get_hidx(&db, &block.header.prev)? {
                                            let _ = index_header(&db, &block.header, Some(&p))?;
                                        } else {
                                            pending_block_requests.remove(&bh);
                                            continue;
                                        }

                                        if let Some(hi) = get_hidx(&db, &bh)? {
                                            let epoch = current_epoch(hi.height);

                                            let local_tip = get_tip(&db)?.unwrap_or([0u8;32]);
                                            if local_tip == block.header.prev || local_tip == [0u8;32] {
                                                let _ = validate_and_apply_block(&db, &block, epoch);
                                                let _ = set_tip(&db, &bh);
                                            }

                                            let _ = maybe_reorg_to(&db, &bh);
                                        }

                                        pending_block_requests.remove(&bh);
                                    }

                                    SyncResponse::Ack => { let _ = request_id; }
                                    SyncResponse::Err { msg } => println!("[sync] error response: {msg}"),
                                }
                            }
                        },
                        _ => {}
                    }
                }
            }

            _ => {}
        }
    }
}

fn hex32(h: &Hash32) -> String {
    format!("0x{}", hex::encode(h))
}

fn handle_gossipsub_event(event: &OutEvent) -> Option<(Option<PeerId>, Vec<u8>, String)> {
    match event {
        OutEvent::Gossipsub(gossipsub::Event::Message { propagation_source, message, .. }) => {
            let topic = message.topic.as_str().to_string();
            Some((Some(*propagation_source), message.data.clone(), topic))
        }
        _ => None
    }
}

fn as_rr_event(event: OutEvent) -> Option<request_response::Event<SyncRequest, SyncResponse>> {
    match event {
        OutEvent::Rr(ev) => Some(ev),
        _ => None
    }
}

async fn handle_request(db: Arc<Stores>, req: SyncRequest) -> Result<SyncResponse> {
    match req {
        SyncRequest::GetTip => {
            let tip = get_tip(&db)?.unwrap_or([0u8;32]);
            let hi = get_hidx(&db, &tip)?.unwrap_or(crate::chain::index::HeaderIndex {
                hash: tip, parent: [0u8;32], height: 0, chainwork: 0, bits: 0, time: 0
            });
            Ok(SyncResponse::Tip { hash: tip, height: hi.height, chainwork: hi.chainwork })
        }

        SyncRequest::GetHeaders { from_height, max } => {
            let tip = get_tip(&db)?.unwrap_or([0u8;32]);
            if tip == [0u8;32] {
                return Ok(SyncResponse::Headers { headers: vec![] });
            }
            let mut chain: Vec<(BlockHeader, Hash32, u64, u128)> = vec![];
            let mut cur = tip;

            while cur != [0u8;32] {
                let hi = get_hidx(&db, &cur)?.ok_or_else(|| anyhow::anyhow!("missing idx"))?;
                let Some(bv) = db.blocks.get(k_block(&cur))? else { break; };
                let blk: Block = bincode::deserialize(&bv)?;
                chain.push((blk.header.clone(), cur, hi.height, hi.chainwork));
                cur = hi.parent;
                if chain.len() > 100_000 { break; }
            }

            chain.reverse();
            let mut out = vec![];
            for item in chain {
                if item.2 >= from_height {
                    out.push(item);
                    if out.len() as u64 >= max { break; }
                }
            }
            Ok(SyncResponse::Headers { headers: out })
        }

        SyncRequest::GetBlock { hash } => {
            let Some(v) = db.blocks.get(k_block(&hash))? else {
                bail!("unknown block");
            };
            let blk: Block = bincode::deserialize(&v)?;
            Ok(SyncResponse::Block { block: blk })
        }

        SyncRequest::SubmitTx { tx } => {
            let _ = tx;
            Ok(SyncResponse::Ack)
        }
    }
}
