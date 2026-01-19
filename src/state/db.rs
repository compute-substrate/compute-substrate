use anyhow::Result;
use sled::{Db, Tree};
use crate::types::{Hash32, OutPoint, TxOut};

pub struct Stores {
    pub db: Db,

    // raw blocks by hash
    pub blocks: Tree, // key: "B"+hash

    // header index by hash -> (parent,height,chainwork,bits,time)
    pub hdr: Tree,    // key: "H"+hash

    // canonical tip hash
    pub meta: Tree,   // key: "tip"

    // utxo set
    pub utxo: Tree,   // key: "U"+(txid||vout) -> TxOut

    // undo logs per block
    pub undo: Tree,   // key: "X"+hash -> Undo

    // app state
    pub app: Tree,    // keyspace described in app.rs
}

impl Stores {
    pub fn open(path: &str) -> Result<Self> {
        let db = sled::open(path)?;
        Ok(Self {
            blocks: db.open_tree("blocks")?,
            hdr:    db.open_tree("hdr")?,
            meta:   db.open_tree("meta")?,
            utxo:   db.open_tree("utxo")?,
            undo:   db.open_tree("undo")?,
            app:    db.open_tree("app")?,
            db,
        })
    }
}

pub fn k_block(hash: &Hash32) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 32);
    k.push(b'B');
    k.extend_from_slice(hash);
    k
}
pub fn k_hdr(hash: &Hash32) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 32);
    k.push(b'H');
    k.extend_from_slice(hash);
    k
}
pub fn k_undo(hash: &Hash32) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 32);
    k.push(b'X');
    k.extend_from_slice(hash);
    k
}
pub fn k_utxo(op: &OutPoint) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 36);
    k.push(b'U');
    k.extend_from_slice(&op.txid);
    k.extend_from_slice(&op.vout.to_le_bytes());
    k
}

pub fn get_tip(db: &Stores) -> Result<Option<Hash32>> {
    if let Some(v) = db.meta.get(b"tip")? {
        let mut h = [0u8; 32];
        h.copy_from_slice(&v);
        Ok(Some(h))
    } else {
        Ok(None)
    }
}

pub fn set_tip(db: &Stores, tip: &Hash32) -> Result<()> {
    db.meta.insert(b"tip", tip)?;
    Ok(())
}

pub fn put_utxo(db: &Stores, op: &OutPoint, out: &TxOut) -> Result<()> {
    db.utxo.insert(k_utxo(op), bincode::serialize(out)?)?;
    Ok(())
}

pub fn del_utxo(db: &Stores, op: &OutPoint) -> Result<()> {
    db.utxo.remove(k_utxo(op))?;
    Ok(())
}

pub fn get_utxo(db: &Stores, op: &OutPoint) -> Result<Option<TxOut>> {
    if let Some(v) = db.utxo.get(k_utxo(op))? {
        Ok(Some(bincode::deserialize(&v)?))
    } else {
        Ok(None)
    }
}
