# Node behaviour notes

Behaviour notes for the node: the reason behind each limit and refusal that a later edit could
plausibly break, what each bound costs, and the tests that pin it. Where this version differs from
upstream, a section says what upstream v1.1.2 (and main `d168f70`) does and why this version does
something else; line citations of the form `d168f70 src/net/node.rs:N` are to upstream main. Unless
a section says otherwise, "the node" is this version and "we", "our" and "us" mean the local node.

## Deferred reorgs and the stall sweep

`try_apply_pending` case 2 (upstream's code) takes a stronger-fork head out of `pending_apply`
before `maybe_reorg_to`, which defers (returns Ok) while an ancestor's body is missing, so the head
waited for the next block (400 s in a test). Here a deferred target waits on the first body missing
on its apply path and goes back into `pending_apply` when that body is stored (`BodyRefetch::wait`
and `note_stored`, `requeue_completable_tip` in `src/net/node.rs`). Pinned by
`tests/p2p_live_stronger_fork_deferred_block_is_retried.rs`: the ancestor answered one poll tick
late, and a complete stored chain below a header tip whose body is never served (the shape a
re-queue of the best header tip alone misses); both fail with the deferral record removed.

The wait map holds at most 256 targets (`MAX_REORG_WAITS`). Evicting the lightest target at the cap
would strand a complete chain when more targets defer on one body, so every attempt that falls
short (`BodyRefetch::note_unreached`) drops the waits of the target's ancestors and records none
under a waiting descendant, so the cap counts branches in either arrival order, and queues the
stored chain under the first block that has no body or a `bad:` mark when it is heavier than the
tip. The guarantee under the waits is the stall sweep (`BodyRefetch::sweep`): once the tip has
stood still for 30 s (`STALL_SWEEP_SECS`, backing off to at most 480 s, `STALL_SWEEP_MAX_SECS`), it
queues the heaviest complete stored chain heavier than the tip (`chain::stored_chain`, the
selection journal-less recovery makes at boot), in slices of 4,096 reads per poll tick
(`STALL_SWEEP_READS`), and stays armed until a search finds nothing. Pinned by the same file's
257-target overflow (about 130 s), its sweep-only case (about 40 s) and `body_refetch_tests`.

## The peer-close log line

Every closed connection logs `[p2p] closed connection to <peer> (<inbound | dialed by us>, <n>
left): <cause>`, the cause being our reason when we disconnected the peer (`disconnect_peer`: idle,
over the peer cap, quarantined, banned and the rest) or the transport's (`io <kind>`, `keep-alive
timeout`, or `closed by the remote or idle` when libp2p gives none). Rate-limited per cause at
powers of two (`log_due`, as for dropped gossip); each line carries the count so far. Quarantine
and ban log only on entry; the p2p loop's fatal line prints the error chain.

A peer's own text, the message of an Err answer, is logged as its length and its first characters
escaped, at most 200 bytes of them (`peer_text`). Printed whole, it lets any peer forge lines in
the node's journal and fill the unit's journal rate limit with one answer of short lines.
`logging_tests::a_peers_text_is_logged_on_one_line_escaped_and_capped`.

## Peer-driven log lines

The class: a log line a remote peer can make the node print at will. Upstream prints one at nearly
every peer event; only GetTip's recv line is sampled, one a peer a minute (`GETTIP_LOG_EVERY_SECS`,
v1.1.2 and d168f70 `src/net/node.rs`). Such lines spend the journal's rate-limit burst for the
unit, and a suppressed interval hides the lines an operator's alerts read. Measured on loopback in
a debug build, without the rule below: one peer at the request throttle wrote 3,600 `[sync-serve]`
lines in 10 s with stored blocks and 7,286 in a minute asking for a block we do not hold (a MISS
line a request); one Headers answer of 1,024 headers past the PoW limit wrote 2,057 lines (a
refusal line and a strike line a header); one identity reconnecting wrote 3,725 lines in 15 s (483
connections), and one address opening connections with fresh identities 16,519 in 15 s (1,672
identities, at its admission caps of 8 established and 16 in handshake, which bound connections at
once, not their rate).

The rule (`src/net/serve_log.rs`): every line that names a remote peer and that the peer's own
messages, connections or answers drive goes through one sampler, keyed by the peer and the line's
kind (`Line`: each request kind, a MISS, an error answer, a strike, a refused header, a gossip
header whose parent we lack, a ban, a quarantine, a connection, an eviction, our request to the
peer, each kind of answer to ours, a failed request, a sync-peer switch, a learned address, a dial
and a failed dial). A peer's first line of a kind is printed at once; after that at most one a
minute, ending `since_last_line=<n>` (`requests_since_last_line` on a request's recv line), the
events of the kind since its last line, this one included. One kind can cover several line texts:
`Asked` our GetPeers, stale-tip and headers requests, `Dial` and `DialFailure` four texts each,
`Evict` five, and a kind of answer, `Connect` and `ErrorReply` two or three; the text printed is the
one whose event found the kind due, and its count includes the events of the kind's other texts. A
GetBlock's lookup and HIT lines and a locator answer's anchor line follow their recv line. When a
peer's last connection closes, one line names its events not printed (`[p2p] <peer> disconnected;
not printed since its last lines: GetBlock=1201 MISS=7280`), at most once a minute; its entry stays
until its lines are a minute old, so a reconnect does not start its minute again, and the poll tick
then drops it with a line for any events still unprinted. Nothing is hidden, only counted; the
counts are lost only when the node stops.

Fresh identities each have a first line, so the rule alone does not bound one address that churns
them (with the ceiling taken out, the live test's 25 s of churn wrote 24,191 lines). A ceiling does:
the sampler prints at most `PEER_LINES_PER_MINUTE` (600) lines in each window of a minute, all peers
and kinds together, a GetBlock's three lines counted as three. A line past it is held back, its
events counted, and the next window starts with one line naming them (`[p2p] peer lines past the
ceiling of 600 a minute: 18080 not printed, for 18080 events: GetTip=2587 ...`). Its "not printed"
counts held printings, not journal lines: a held GetBlock stands for its three lines, a held locator
or failed request for two. New peers get entries only while the window has room. An entry stays
while its peer is connected or has had a line due, printed or held, in the last minute, and the poll
tick drops it within 5 s after that; a held line refreshes its kind's minute, so the entries are
bounded by the identities that come back within a minute, not by the lines printed (memory under a
flood: below). 600 is 3.3 times the busiest minute of a mainnet node's hour under the per-peer rule
(180 lines; 13,682 lines of these kinds in that journal hour, 7,048 under the rule, a replay over
the lines' peers and times).

Not through the sampler, and why: lines already counted at powers of two (`log_due`: a connection's
close line, an inbound handshake failure, the request throttle's line, gossip drops, inbound
request failures, a banned peer's connect, a dial our limits refuse); lines a peer pays proof of work
for (our block requests and their blocks, bodies refused for a header we indexed, reorgs, a
canonical provider: each needs a header at its height's difficulty, at least the PoW limit, 2^24
hashes); lines for a tx the mempool admitted (its fee); the poll tick's own lines (`[mem]`, the queue
status, the cap and reserve summaries, once a tick); our configured bootnodes' dials; and the RPC's
lines (`[tx_submit]`, from RPC callers, not peers). A ban and a quarantine go through the sampler
but are printed every time for one identity, as each recurs only after its 300 or 600 s; only the
ceiling can hold one back.

Measured with the rule, the same setup: one peer sending every request kind in turn at the throttle
for 62 s (stored, missing and non-binding blocks, GetHeaders, locators, GetTip, GetPeers, SubmitTx,
and invalid requests below the quarantine), 8,393 served and 66,231 answered "rate limited", wrote
19 lines; one identity reconnecting for a minute (1,797 connections, a GetTip and a missing block
each) wrote 35 lines, 12 of them `[mem]`; a missing block at the throttle for a minute, 23 (12
`[mem]`); one Headers answer of 1,024 refused headers, 11; fresh identities from one address for
25 s (2,648 identities), 500 lines in the window, and the next window's first line named the 18,080
held back. A window is fixed, so a sliding minute can hold two windows' lines, 1,202 with their
summary lines, and late lines of the window before: a GetBlock's lookup and HIT lines and a
locator's anchor line are counted with their recv line but print when the serve runs, up to 15 s
later (`RR_REQUEST_TIMEOUT`), at most 400 counted in one window (200 GetBlocks). A sliding minute
holds at most 1,602 sampled lines.

The residual: the ceiling bounds the sampled lines however many addresses an attacker has, but in a
flood it holds back honest peers' lines with the attacker's (counted in the summary, not printed),
and the lines it does not take are bounded as above, not by it. The flood is cheap: in the live
test's churn the first 64 fresh identities from one address filled a window (500 lines), about half
a second at the test's pace of 3,256 identities in 25 s, so about 64 fresh connections a minute from
one address keep the ceiling full. Bans, quarantines and sync-peer switches are then held too and
appear only as kind counts in the next window's summary line (`ban=`, `quarantine=`, `sync-peer=`),
without the peer; the ban or quarantine itself applies either way.

The sampler's memory under a flood: an entry is 728 bytes (an 80-byte peer id and 27 kinds of 24),
1.0 to 1.6 KB with the hash map's spare room, kept for each identity the flood reconnects within a
minute. In a probe of the sampler (each window 600 fresh identities, then every older one back with
its line held, the tick pruning every 5 s) the entries were 6,000 after 10 windows and none 70 s
after the flood stopped; the map keeps its largest allocation (std's HashMap does not shrink), and
later entries reuse it. The admission caps bound connections at once, not their rate, so this grows
with the attacker's reconnect rate; nothing the node decides reads the map.

An operator who runs the node under systemd and reads specific lines from the journal (an alert on
`[tx_submit] ACCEPT`, say) needs the unit's journald burst above the sampler's 600 a minute plus the node's other lines: a
burst of 5,400 a minute leaves room; one of 500 a minute does not, under a flood at the ceiling.

Pinned by `tests/p2p_live_serve_log.rs` (one peer's minute of every request kind at most 60 lines,
red with the MISS at every request; fresh identities from one address at most the ceiling a window,
red without it; one Headers answer of refused headers at most 16 lines, red with its refusal line at
every header; a peer that goes again within the minute of its disconnect line, its events named by
the poll tick's `gone` line once its lines are a minute old and not before, red without the tick's
prune, the only caller of `prune` and what bounds the entries; each with its honest path asserted
and the counts added up) and `net::serve_log::tests` (the minute, a reconnect, the ceiling).

## Block-request failures

A failed GetBlock stamps the peer only when another block server is connected. The
request-response handler runs at most 4 streams per connection, inbound and outbound together, and
refuses an outbound request past that on our side ("max sub-streams reached"); that refusal is our
limit and blames nobody (`is_local_stream_refusal`: no score, stamp or sync-peer switch; the peer is
passed over for 1 s). Nor does a ConnectionClosed on a second inbound connection the poll tick shed
("Connection admission"; `OutboundFault::OurShed`, the peer keeps its other connection and is not
passed over). The attribution is conservative where our close overlaps a failure of the
connection: a connection already failing on the transport whose close the swarm has not reported
yet is still established when the tick sheds it, `close_connection` returns true (swarm 0.48.0
`lib.rs:656-663`; closing a connection that is already closing has no effect,
`connection/pool.rs:192-202`), and its ConnectionClosed failures are counted ours, so the peer is
not blamed for that overlap. Any other failure on a shed connection (a timeout, a transport error),
and a ConnectionClosed on a connection we did not shed, is the peer's.

A shed connection's failures reach the loop after the ConnectionClosed event that ends its `shed`
entry: request-response 0.30.0 queues them at the close (`lib.rs:658-701`), and the loop handles
them in event order, with no bound in time, since its other arms can run in between. So every
request of ours is recorded from its send to its answer or failure (`src/net/unreported.rs`; all go
out through `send_our_request`), and at the shed connection's close the peer's requests the layer no
longer holds as pending (`is_pending_outbound`, `lib.rs:523-544`), those with a report queued, keep
the connection counted as shed until each has been reported. The record holds only requests in
flight, and connection ids are not reused. Remembering the closed connection for a fixed time
instead is not enough: a loop held past it between the close and the failures (a slow store read in
the tick) blames the peer again, which costs an honest peer -1, a 120 s stamp for the block and its
place as sync peer. Tests:
`p2p_live_inbound_saturation::a_shed_connection_carrying_our_block_request_blames_nobody` (an honest
peer's second connection shed with our GetBlock in flight on it, its score 0 and no stamp; red:
score -1 and the block stamped),
`p2p_live_inbound_saturation::a_shed_connection_is_remembered_until_its_failures_are_handled_however_late`
(the same with the node polling no swarm event from the close until a poll tick at least 6 s later,
`TEST_HOLD_SWARM_AFTER_SHED`; red with a 5 s record: score -1 and the block stamped),
`unreported::tests` and
`block_request_failure_tests::a_connection_we_shed_blames_nobody_and_the_peers_own_failures_still_do`.

Of the other failures only a request timeout also costs the peer a `timeout` in its quality record
("Peer score"). At most 2 block requests are in flight to one peer (`MAX_BLOCK_REQUESTS_PER_PEER`),
leaving the other streams to tip, header and peer requests and to the peer's own. The
request-response layer fails every request on a live connection within about 25 s (10 s stream
upgrade, 15 s request timeout), so the poll tick's in-flight sweep only frees a slot nothing
reported on in 60 s (`BLOCK_REQ_TIMEOUT_SECS`) and blames nobody. An answer the node drops (from a
peer banned or quarantined since the request, or one that is neither a block nor an error) frees
its block-request slot at once (`release_unanswered_block_request`) instead of holding it for that
60 s. An answer of the wrong kind also stamps that peer for the block and drops it as the block's
recorded provider (`note_wrong_kind_block_answer`): this node's server answers GetBlock only with
the block or an error, and since the answer comes at once no timeout moves the request, so without
the stamp a peer that answered `Ack` to every GetBlock would hold a block it had announced while an
honest peer had it. It takes no score, and an answer dropped for a ban or quarantine adds nothing.

An "unknown block" answer stamps the peer for the block whatever the server count (it comes at
once, so without the stamp the sole server would be asked again in a loop), requeues the block and
drops the peer as the block's recorded provider, so the next request goes to another server
(`note_unknown_block_answer`). Nobody is scored for it, the provider included. Upstream scores every
such answer -3 (`SCORE_BAD_UNKNOWN_BLOCK`, d168f70 `src/net/node.rs:75`, applied at `:4486`), also
one to a request it did not track, while `pump_blocks` asks any connected peer, so an honest peer
asked for ten bodies of a branch it does not hold is quarantined. The recorded provider's answer is
honest too: a peer serves a body before it validates it, its own apply can blame and drop that body
(`chain::body_fault`), and it then answers "unknown block". A provider that announces and never
serves costs one request per block per `BAD_PROVIDER_RETRY_SECS` (120 s). Pinned by
`tests/p2p_live_invalid_provider_fallback.rs` (both tests: the provider without the bodies is never
scored, and the blocks come from the other peer) and
`block_request_failure_tests::an_unknown_block_answer_costs_no_score_and_the_retry_goes_elsewhere`.

Inbound failures, on requests a peer sent us, are logged (one power-of-two line) and never counted
against the requester. Upstream disconnects a requester at 20 in 60 s (d168f70
`src/net/node.rs:4633-4657`); none of the failures libp2p-request-response 0.30.0 reports is the
requester's doing, so the rule is not kept. A request we cannot read or decode, or one over its
kind's size limit, fails before the layer registers it and is only traced (`lib.rs:1001-1018`); the
handler's events are private (`lib.rs:72`) and the codec does not know the peer, so that refusal
cannot be counted here, and it costs us the read of at most its kind's limit. An IO error is
reported only for a registered request, so it is our own write or close failing
(`handler.rs:149-157`): the codec refusing an answer at or above the 1 MiB wire cap (a stored block
between 1 and 2 MiB), or the stream or the connection gone; counted, 20 answers refused in a minute
would disconnect the requester. A late answer to a requester that has given up is written without
error: its yamux drops the request stream after its FIN without a reset and ignores data for it
(yamux 0.14.1 `connection.rs:541-550`, `:680-695`; measured: 25 answers written after the
requester's 100 ms timeout, no inbound failure). A Timeout is our own late answer (libp2p's inbound
timer covers the wait for our response, libp2p-request-response 0.30.0 `handler.rs:136-158`), and a
ConnectionClosed or a ResponseOmission is not the requester's either; under upstream's rule, which
counts every kind, a loaded serve can get an honest requester disconnected. A ResponseOmission is an
answer we dropped: a request from a banned or quarantined peer is dropped unanswered (the
`Event::Message` arm), so counted, a quarantined peer that kept asking would be disconnected as
noisy at 20 such requests a minute; here it stays connected, unserved, until its quarantine ends (a
banned one is closed, "Connection admission"). 0.30.0 never reports an unsupported protocol (no
construction site; its handler's listen upgrade error is unreachable, `handler.rs:248-256`), so the
node keeps no per-requester failure counter at all, and no map that grows by one entry per identity
that ever failed a request. Tests: `tests/p2p_live_inbound_failures.rs` (25 answers the codec
refused, 25 late answers and 25 unreadable requests each leave the requester connected and its next
request answered; red at the 20th refused answer when an IO error counts).

## Outbound pacing

An upstream server bans a requester for ten minutes past 120 requests in its own 10 s window
(`allow_rr_req`, d168f70 `src/net/node.rs:53`; `UPSTREAM_RR_REQS_PER_WINDOW`), a window that starts
at its first request after the last one ended, so its start is not ours to see. We send one peer at
most 90 block requests (upstream's `OUTBOUND_MAX_RR_PER_PEER_PER_WINDOW`) in any 10 s: the pacer
counts our sends of the last 10 s (`pace_saturated`, `pace_note_sent`), every block request is
paced, the immediate request on a new child header included (both senders go through
`can_take_block_request` and `note_block_request_sent`), and a check opens no window. On top of
those the background requests are unpaced and at most 5 in any 10 s (a GetTip at first sight and at
each 5 s poll tick while our tip is stale, so at most 3, a headers request every 20 s and a peers
request every 30 s, one in flight per peer), 95 in all, and a stall of the server can bunch only
what we hold in flight (two block requests and one background request per request timeout).
Upstream's own pacer is a tumbling window per peer that a check opens (`:1059-1079`), and its
immediate request is not paced: demand that comes late in a window sends 90 at its end and 90 more
when it resets, 180 inside one window of the server, enough for an honest server on upstream's rule
to ban the requester during a fast catch-up (in a replay, 140 sent and banned after 2.43 s). The
throughput here is the same 90 a window. Tests:
`peer_state_tests::our_pacing_never_crosses_an_honest_servers_request_limit` (the real pacer against
the real `allow_rr_req` on a virtual clock, with the background requests, and a 60 s catch-up that
still sends 90 a window),
`peer_state_tests::a_block_request_is_paced_and_recorded_whichever_sender_sends_it` and
`peer_state_tests::the_request_throttle_and_invalid_message_ban_fall_at_their_figures` (the 1,200th
request served and the 1,201st throttled with the peer not banned, and the peer banned at its 32nd
invalid message and not at its 31st).

Our own server throttles, and never bans, past 1,200 requests in a window in every mode
(`RL_MAX_RR_REQS_PER_WINDOW`, upstream's bootnode figure, d168f70 `src/net/node.rs:54`): the rest of
the requester's window is answered `Err "rate limited"` at once, before the serve permit, and the
requester is kept, not banned, not quarantined, its connections open and its gossip taken, and served
again in its next window (`RrAdmission::Throttled`; one log line per throttled window at powers of
two). Upstream bans past 120 for ten minutes outside a bootnode (`:53`, banned past it at
`:1132-1134`), which can drop an honest upstream node, and here a ban also closes its connections
("Connection admission"), which would cost the gossip of a producer on upstream's code. 120 is not a
bound on what an honest upstream requester sends in one of our windows: its pacer allows 90 block
requests per window of its own (`:71`), a tumbling window per peer opened by a check
(`:1059-1079`), so up to 180 fall in one of ours; its immediate GetBlock on a headers answer is
unpaced and goes to the block's recorded provider whichever peer answered (`:4156-4195`); and its
pacer map is a thread_local (`:1054-1057`) read from a loop spawned on a multi-thread runtime
(`:2529`), so a loop polled on several worker threads paces each thread's sends apart. A mainnet
node on the 120 rule banned one external peer 38 times in about 19 hours, 37 of them 6 to 108 s
after its last connect line (read from its journal).

1,200 is a policy threshold, not a ceiling on an honest upstream node: by the reading above its
block-request pacer allows about 180 per worker thread in one of our windows, and its
`#[tokio::main]` (`src/main.rs:13`) runs one worker thread per core, so a node of 7 or more cores
(7 x 180 = 1,260) catching up mostly from us could pass 1,200 in one of our windows, given the
throughput: with MAX_INFLIGHT_BLOCKS 8 (`:103`) and no per-peer cap, 1,200 in 10 s takes about 120
answers a second from us (derived, not measured). What it gets past the figure is only "rate
limited" answers for the rest of that window: no ban, no close, its connections and gossip kept.
What a throttle costs an upstream requester: its Err arm (`:4541-4559`) stamps us a bad provider of
the requested block for 120 s (`BAD_PROVIDER_RETRY_SECS`, `:84`, read at `:2036`) and requests the
block from another peer, charging nothing else, so for that block it stays off us for longer than
our 10 s window; for a GetTip, headers or peers request the Err answer is only logged. The Err
answer is the cheaper refusal: a dropped answer is an OutboundFailure (`:4573-4631`), a timeout in
its quality record, -1 to our score for a block request, the same stamp, and its sync peer switched
away from us. The text avoids "unknown block" (-3, `:4486`) and "historical" (header-only,
`:4547-4549`).

What the figure still protects: the answers one identity gets in a window, 120 a second, the cheap
ones included (a GetTip; a GetPeers, which is answered on the loop); past it a request costs a decode
and an Err answer, no store read. Identities are cheap, so the figure is not what bounds the serving
cost: every request but GetPeers waits for the one serve permit ("Serving requests off the loop"),
so store reads stay one at a time whatever the figure, and one identity holds at most eight
requests open (four streams a connection, two connections a peer), each leaving the queue once its
stream is gone or 15 s after it was read. Tests:
`peer_state_tests::a_request_flood_is_throttled_for_its_window_and_never_banned` (the 1,201st
throttled, the peer not banned, served in the next window; red on the ban),
`p2p_live_connection_admission::a_request_flood_is_throttled_for_its_window_and_the_peer_kept` (a
peer past 1,200 is answered "rate limited", stays connected past a poll tick, its gossip reaches the
node's checks and its next window is served, beside an honest peer; red on the ban: its connection
was closed) and the boundary pins above.

## Header serving

Both GetHeaders handlers take each header from the `hdr_raw` tree when its bytes hash to the block,
else from the stored body, writing `hdr_raw` then (`served_header`), so a header is decoded from its
body once. GetHeadersByLocator reads headers for the lowest `max` blocks above the anchor it
answers. Upstream reads and decodes every body above the anchor, all of them for a genesis-anchored
locator (d168f70 `src/net/node.rs:4797-4835`). The tree grows by one header per canonical block
served.

The anchor is the highest locator hash on our chain (genesis for the zero hash). While the txid
index's height index is fresh at the tip, the anchor and the hashes above it come from it
(`locator_anchor_by_height_index`: a few reads per locator hash, one per answered height); while it
is stale, for a moment after each block and during its rebuild, the node walks the header index
down from the tip to the anchor (`locator_anchor_by_walk`). Upstream walks on every answer
(`:4763-4785`), so a node syncing from genesis costs its server a walk of the whole chain per 1,024
headers, growing with the square of the height. The index is checked fresh at the tip again after
its entries are read, also before an answer of "no anchor", and the node walks from the tip it
captured when the tip has moved: the reconciler rewrites the height entries of a reorg and moves the
freshness marker in the same batch as each, so between the two checks a reorg could otherwise give a
coherent suffix of the new chain above an anchor on the old one, or no anchor where the walk finds
one. Residual: a tip that leaves and returns within one answer passes both checks; the answer is
still a linked chain of headers. Either way the answer stops at the first header that cannot be read
or does not link to the one before it, so it connects to the anchor. Pinned by
`header_serving_tests::a_fresh_height_index_anchors_a_locator_without_the_walk` (the two paths
give the same answers; a height entry naming another branch ends the answer) and
`header_serving_tests::a_reorg_indexed_during_a_locator_answer_falls_back_to_the_walk_of_the_captured_tip`.

## Serving requests off the loop

Inbound requests other than GetPeers (which reads the loop's address book) are served on the
blocking pool and answered from the loop when their serve returns (`Serves`, the loop's serve arm):
only the loop holds the swarm, and libp2p's `send_response` needs it. Upstream (v1.1.2 and d168f70,
`src/net/node.rs:3767-3777`) awaits each serve in the loop's select! arm: peers asking for headers
or blocks hold the loop that also handles gossip, sync answers, block apply and the poll tick, and
its one-permit "server busy" semaphore, always free when the next request is read, never refuses
(measured in a release build: an honest GetTip at p50 32 ms and p99 105 ms under 40 peers at 11
GetHeaders a second). Here the serves still run one at a time (`SERVE_PERMITS`), so serving costs
the host what it does upstream, and a request waits for its turn rather than being refused: an
honest node pipelines up to four requests on one connection (upstream's
`with_max_concurrent_streams(4)` and MAX_INFLIGHT_BLOCKS 8 with no per-peer cap, d168f70
`src/net/node.rs:2653-2654`, `:103`), and a "server busy" answer to its GetBlock would stamp us a bad
provider of that block for 120 s (its Err arm, `:4484-4560`).

A waiting serve ends unserved, and leaves the semaphore's queue, once its request's stream is gone
(the request timed out or its connection closed; checked every 500 ms, `SERVE_WAIT_CHECK`) or 15 s
after the request was read (`RR_REQUEST_TIMEOUT`; libp2p's timer starts at the stream, before the
read), whether or not its turn has come (`wait_for_turn`). So the waiting serves are at most the
inbound request streams open, four a connection shared with our own requests, and those whose
stream ended within the last 500 ms. A serve that waited for its turn before it checked its
requester would keep, behind one stalled serve, every expired request queued with its decoded
request, channel and store handle, and each stream its timeout freed would let another in
(`expired_requests_leave_the_serve_queue_behind_a_stalled_serve`: one headers serve held 40 s while
a requester keeps three GetTip in flight, 4 serves pending at 37 s, 10 without the check, and its
live requests served once the held serve returns). The 500 ms check is what frees the place of a
request whose connection closes while it waits; the deadline alone would hold it up to 15 s after
the read (`queued_requests_leave_once_their_connection_closes_not_at_their_deadline`: three requests
queued behind a 10 s serve leave 0.5 s after their connection closes and another requester's queued
request is answered after the serve; red with the check removed, 5 serves still pending 3 s after
the close). A serve already running keeps its permit until it returns, its requester gone or not: a
blocking store read cannot be cancelled. The refusal to serve a block whose header fails our PoW
checks or whose merkle root does not bind (`outbound_block_refusal`) runs inside the serve.

Measured on loopback in a debug build (`tests/p2p_live_serve_off_loop.rs`: six peers each keeping
four GetHeaders of 1,024 headers in flight at 11 a second against a 1,100-block chain, a probe asking
for peers every 25 ms): GetPeers on the loop answered at p50 1.6 ms, p90 1.9 ms, max 3.2 ms, 200 of
200, and every one of 268 pipelined header requests answered with its headers; with the serve
awaited on the loop, p50 117 ms and max 212 ms in one run, and in another the probe's first request
still unanswered after 5 s. Residual: the serves are one queue, so under such a flood an honest
peer's GetTip or GetBlock waits behind the flood's requests, up to the 15 s timeout when many
identities keep their four streams full; the loop, our own sync and gossip do not wait. An honest
request can also be dropped before it is read: the four streams of a connection are shared by both
directions (`with_max_concurrent_streams(4)`, upstream's), and the handler drops an inbound stream
that finds them full, reporting it to neither side's application (libp2p-request-response 0.30.0
`handler.rs:164-170`); the requester sees its request fail, and an upstream requester's
OutboundFailure arm charges that to us (d168f70 `:4573-4631`). We keep at most two block requests
and one background request in flight to a peer, so on one connection an honest peer's second
concurrent request to us can be dropped. Inherited from upstream, whose own block requests (8 in
flight, no cap per peer, `:103`) fill a connection the same way.

## Header index growth

`index_header` checks a header against its parent and has no floor, and both net arms index any
PoW-valid header whose parent is known; the index is never pruned. Below height 2 the expected bits
are the parent's, so a sibling of block 1 costs about 2^24 hashes. A side branch anywhere else gets
there too: a replay of `expected_bits_strict` (45 headers at bits 0x1a67c4e0, 120 s apart, then side
headers 12 T apart) lowers the bits from the second side header and reaches the PoW limit at the
80th, after about 4.58 blocks of work at the starting difficulty (3.18e15 hashes, about 36.8 days at
1 GH/s), and from there each sibling costs about 2^24 hashes. So a peer with a GPU can grow the
header index and the disk, and every indexed header adds a read to a stall sweep. One other reader
walks the whole index: `best_header_tip` in `recover_if_needed`, at a boot that finds a reorg
journal (a crash mid-reorg); its `#[allow(dead_code)]` is stale. Journal-less recovery takes its
candidates from the stored bodies. Upstream has the same exposure.

Not bounded here; an operator's disk alert is the signal. A fixed minimum chainwork (Bitcoin Core's
`nMinimumChainWork` without its presync) is not a fix: it refuses the first header of a heavier
competing branch whose fork point is below the constant, and every later header of that branch then
lacks an indexed parent, however shallow the reorg is for the node; a floor without a presync step
is a chain-selection rule. The fix, if junk headers ever show up, is Bitcoin Core's header
pre-synchronization (`src/headerssync.h`; `GetAntiDoSWorkThreshold` and `TryLowWorkHeadersSync` in
`net_processing.cpp`): download a low-work branch's headers once to count their work without storing
them, and re-download and store them only when the branch has proven enough work.

## Top-k apply cost

Every Propose and Attest runs `recompute_topk` (`state/app_state.rs`): it reads every score key of
its epoch and domain (the prefix `S | epoch | domain_len | domain`), sorts them and rewrites the
stored top-k with an undo entry. A block's apply time therefore grows with its Propose and Attest
count times the proposals scored in that epoch and domain, bounded by the block caps
(`MAX_BLOCK_TXS`, `MAX_BLOCK_BYTES`), by the epoch (`EPOCH_LEN` blocks; the score keys embed the
epoch) and by the fee each of those transactions pays, which a miner filling its own block takes
back in its coinbase. Every node pays it when it applies the block and again at every boot, since
the rebuild replays every block.

Not changed in this version: it is consensus apply code, identical to upstream's. The top-k bytes
are in the app tree that `fingerprint()` hashes into `app_root`, so any difference from upstream's
result forks a node off the chain that nodes on upstream's code build. An incremental top-k must
first be proven byte-identical to this one (golden vectors and a differential of the two functions
over the mainnet replay and random sequences; neither exists), and every node has to adopt it
together, since a node that changes it alone forks.

The figure to watch is the count of proposals scored in one epoch and domain: the score keys under
its prefix, one per proposal proposed or attested in that epoch, counted on a datadir copy. The cost
of each Propose and Attest is linear in that count, and no figure is recorded here: the count at
which it matters is measured by timing one Attest's `apply_app_tx` against a store holding N score
keys under one prefix, for growing N, and multiplying by the Proposes and Attests one block can
carry.

What would move the count: upstream's `csd_anchor` (main `d168f70`, `src/bin/csd_anchor.rs`), a
client that splits a wallet's coins and signs one Propose per unit of a git repository into one
domain (`math/openai-math` by default) in one run, so they land in the epoch of the blocks that mine
them, and invites Attests on each; its README (`anchor/README.md`) names 719 manuscripts as its
first target.

## `/health` `ok`

`/health` `ok` is false while a supervised task (p2p, the txid reconciler, the miner) has exited or
panicked (`SUBSYSTEMS.all_healthy()`), still answered as 200, so a monitor that checks only the
status sees no change; `/node/info` `subsystems` names the task. Upstream answers `ok: true`
unconditionally (d168f70 `src/api/mod.rs:419-428`), so a node with a dead p2p task answers ok with
a frozen tip.

## The address index

`/utxos/:addr20` reads one address's unspent outputs from an address index
(`src/state/addr_index.rs`). Upstream scans the whole UTXO tree on every call (d168f70
`src/api/mod.rs:1517`), about 0.45 µs a row: 62 to 68 ms a call over 130,000 UTXOs. Inside this
version's six-permit heavy-scan gate, a few clients reading balances at a steady rate fill the gate
and shed everyone else's balance reads. Without the index, `?lifetime=true` here also reads every
block body (`lifetime_walk`).

Layout, all in the `idx` tree: `a/<addr20><outpoint>` for each unspent output, the outpoint written
as the UTXO tree keys it (txid, then vout little-endian), so an address's prefix scan visits its
outputs in the UTXO tree's key order, the order the scan reports; `ao/<outpoint>`, the address an
unspent output pays, read when a block spends it; `au/<block hash>`, the outputs indexing the block
removed or replaced, with their addresses; `al/<addr20>`, the address's lifetime coinbase totals.
The txid-index reconciler writes it: per block, in the same `sled::Batch` as the block's locators
and the completeness marker `idx:tip_hash`, it replays the block's UTXO changes in the order
`validate_and_apply_block` makes them (each non-coinbase transaction spends its inputs, then
creates its outputs; the coinbase's output last) and records what it replaced, so taking the block
back out on a reorg restores exactly the entries the block found. Nothing in the block apply path
writes it (`tx_scan.rs` HARD RULE 1).

Lifetime totals. `al/` holds an address's `mined` total exactly, as a u128, and its count of coinbase
outputs as a u64 (one a coinbase), 24 bytes a value. Indexing a block adds its coinbase to them and
taking the block back out subtracts the same amounts (`add_lifetime`), so a reorg restores the
totals the block found, whatever their size; a stored total capped at u64::MAX would make that
subtraction leave a wrong total. A read serves `mined` capped at u64::MAX
(18,446,744,073,709,551,615 base units), because `/utxos` serves a u64 and the scan's block walk
saturates at that value (`lifetime_walk`), so both paths give the same answer. A total past u64::MAX
is reachable: a coinbase pays its block's reward plus the block's fees (`validate_and_apply_block`),
a miner may fill its own block with transactions that pay its own coins as fees, and `src/` has no
coinbase maturity rule, so the same coins come back in that coinbase and can be spent the same way
in the next block it mines. The bound is the capital recycled times the blocks mined, not the
supply: recycling 1,000,000 CSD takes 184,468 such coinbases, and recycling the 3,812,298.8 CSD the
dominant miner was paid over its 76,236 coinbases to height 133,044 takes 48,388.
`lifetime_limit_tests::lifetime_totals_past_u64_max_are_stored_exactly_served_capped_and_taken_back_out`
indexes a block past the limit, reads the exact stored total and the capped answer from both
paths, and takes the block back out to the exact total before it.

A read uses the index only while `idx:tip_hash` equals `meta:tip`, checked before the read and
again after it (`read_via_index_at`), and takes each output's membership and fields from the UTXO
tree (`get_utxo` and `get_utxo_meta` per candidate): the index proposes outpoints and the UTXO tree
decides, so an index entry adds no output to an answer
(`a_stray_index_entry_adds_no_output_and_the_check_names_it`). Otherwise the read is the scan's,
the whole UTXO tree and, on `?lifetime=true`, the block walk, and not a partial answer from an
index that does not cover the tip: on the first start after the idx layout changes (`IDX_VERSION` 3
resets the idx tree and the reconciler rebuilds both indexes from genesis), for the moment after
each block until the woken reconciler has indexed it, and while the reconciler fails. `/node/info`
`tx_index_converged` covers both indexes.

Each answer names the tip it was read at, `tip` ("0x" and 64 hex digits, the last field; null when
`ok` is false), from either path (`utxos_tests::the_answer_names_the_tip_it_was_read_at`); upstream's
answer has no such field, and a reader of named fields is unaffected by it. A read is still not a
snapshot. While a block B is applied on tip A, from its first UTXO write until `set_tip(B)`, both of
the index path's checks still see tip A, so the index answers the address's outputs at A less those
B has spent so far and none of B's new ones, where a scan in the same instant answers the UTXO tree
as B's writes have left it so far; both say tip A. Neither can make a wrong spend (the wallet
verifies each input it spends and the node every spend): both are a torn read within one call. A
read that starts at tip A while B is applied, indexed, reorged out and unindexed back to A passes
both checks though it may have seen part of B (an ABA, two tip moves within one read), a class the
scan shares.

Why this design. What the index has to keep is that no crash leaves it disagreeing with the UTXO
set in a way that changes an answer. Writing the index in `put_utxo` and `del_utxo` would turn every
UTXO write of block apply into a two-key write and put the index's failures inside block
validation, where a failed index write rejects a valid block. This design gets the property without
touching the apply path: sled recovers a batch whole (`apply_batch` seals it), so after any crash
the index covers exactly the blocks up to its marker; a read uses it only while the marker is the
tip; the UTXO tree decides membership; and at a marker equal to the tip the index's outputs are the
UTXO tree's, both being the replay of the same chain, with the UTXO tree rebuilt from genesis at
every restart. An index of created outputs that keeps them after a spend would not help the address
a caller who wants to load the node picks: on the mainnet chain to height 129,403 the dominant
miner's address had 75,002 outputs ever created and 307 unspent, against 73,071 UTXOs in all, so
for that address a created-output index costs about as much as the scan. This index drops an output
when a block spends it, and a read costs the address's unspent outputs.

Equal to the scan. `tests/addr_index_replay.rs` applies a generated chain through `maybe_reorg_to`
(16 addresses, signed spends, some of outputs made earlier in the same block, reorgs of depth 1, 2,
4, 8 and 16) and compares the index's read with the scan's for every address at each of its 106
tips, 1,696 reads. The two blocks before the depth-2 reorg repeat an earlier coinbase's txid while
its coin is unspent: one overwrites the coin, and one spends it in a transaction of its own and then
recreates it, which the index applies as no change that still records the owner; the reorg takes
both blocks out and keeps the coin's own block, so the index restores the owner from those records.
The test asserts that each block did what it was built for and that the coin is back at its own
block's height after the reorg. Each comparison requires the same outputs in the same order with
the same height and coinbase flag, the same tip height and lifetime totals, from which every field
and total `/utxos` serves follows (`api::utxos_resp`); before the reconciler runs at a tip, the
read is the scan's. On the mainnet chain to height 133,044 (`tests/addr_index_mainnet.rs`, a
measurement run on a block file): 1,823 addresses, 70,522 UTXO rows and 70,522 index entries, no
difference. `csd utxo-index-check --datadir <dir>` runs the same comparison (`check_against_scan`)
on a datadir, for a copy of a stopped node's, and exits 0 only when every address agrees; it refuses
what `csd fingerprint` refuses, and an index that is not current at the tip unless `--build-index`
first builds it, which writes that datadir's idx tree. That build exits nonzero, naming the height
and hash, at a canonical block whose body the datadir lacks, where the node's reconciler waits for
the body from its peers (`tests/utxo_index_check_cli.rs`).

Crashes. `tests/addr_index_crash.rs` kills a process that applies blocks and reorgs and runs the
reconciler with SIGKILL at 16 random moments, recovers the datadir as a booting node does
(`recover_if_needed`) and requires every address's read to equal the scan's whichever path answers
(in one run the index answered 48 of the 192 reads right after a recovery and the scan 144; the
split follows the kill moments, which are timed sleeps, so where each lands is not recorded; SIGKILL
keeps the kernel's page cache, so the test covers what sled had not yet written from its own
buffers, not a power loss), then the index to equal the scan for every address once the reconciler
caught up. Two cases are fixed by hand: a read that a new block overtakes falls back to the scan,
and an index batch that outlived its block's state (the marker past the tip) leaves every read to
the scan until the reconciler takes the block back out.

Rebuild. Every restart rebuilds the state from genesis (`recover_if_needed` calls
`rebuild_state_to_tip`, which clears utxo, utxo_meta, undo and app and replays) and leaves the idx
tree alone, so when the rebuild returns `meta:tip` is the marker again and the index answers at once
(`a_restart_rebuilds_the_state_and_the_index_is_current_without_rework`; on the mainnet chain a
restart's rebuild of 133,045 blocks took 63.6 s and 69.0 s and the index was current right after
it). The index costs rebuild time once, on the first start with idx version 3. On the same chain,
with one plan kept across the ticks as `run_reconciler` keeps it, the cold build of the idx tree
took 23.2, 26.9 and 23.5 s of reconciler work (15.5 to 16.9 s of the thread's CPU), against 12.4,
16.6 and 13.5 s (5.8 to 6.4 s of CPU) for the txid index alone: three pairs run alternately on one
datadir (release build, nice 19, 1-minute host load 7.5 to 15.9 at the starts). The address index
adds about 10 s of work, and the reconciler's sleeps between catch-up ticks add 52 s either way
(1,039 ticks of 128 blocks, 50 ms each). Those parts add up to an estimate for that chain with no new
blocks arriving, not a timing of a deployment: the first start with idx version 3 has the index
behind the tip for about 78 to 83 s, the reset of the old tree (2.8 to 3.8 s) included. A plan built
anew every tick walks the remaining headers again each time, which hides the address index's share
in that walk; `tests/addr_index_mainnet.rs` keeps one plan too, and in one run, after importing the
chain into a fresh datadir and rebuilding its state, its cold build of both indexes took 41.1 s of
work.

Size at height 133,044, keys and values: `a/` 70,522 entries, 4,090,276 bytes; `ao/` 70,522
entries, 4,160,798 bytes; `au/` 133,045 entries (one a block), 19,749,271 bytes; `al/` 882 entries,
41,454 bytes. 28,041,799 bytes in all, against 57,702,222 for the whole idx tree.

Cost, on that chain (release build, on a loaded host, the least of five index reads, of three scans,
and one block walk): the median holder's read (3 UTXOs) takes 12.5 µs through the index and 55.4 ms
through the scan; the largest holder's (4,748 UTXOs) 17.2 ms and 58.4 ms; the dominant miner's (331
UTXOs, 76,236 coinbase outputs) 0.85 ms and 56.7 ms, and with `?lifetime=true` 0.85 ms through the
index against 488 ms with the block walk; an address with nothing 7.5 µs. The heavy-scan gate keeps
its six permits. A read through the index costs its address's unspent outputs, not the UTXO set, so
honest reads no longer scale with the set; nothing bounds it by the scan's cost. Two later runs on
the same datadir (thread CPU time, the least of three to nine reads, three for the synthetic
address's scans below, 1-minute host load about 15; their scans read 32 to 50 ms where the first
run's read 55 to 58 ms, so absolute figures move by up to about 1.8 times between runs) gave the two
rates: the scan 0.456 and 0.545 µs a row (an address with nothing, 32.2 and 38.5 ms, divided by the
70,522 rows), the index 1.9 to 3.4 µs an output (the three largest holders, 4,748, 2,717 and 1,439
UTXOs). So an index read of about 11,000 to 17,500 outputs costs a scan of today's set. Outputs paid
to one address are rows of every scan as well, so for that address the two cross further out: with
synthetic outputs of value 1 added to that datadir for one address, its index read was 0.27 and
0.30 of its scan at 5,000 outputs, 0.66 at 20,000 in both runs, 0.87 and 0.86 at 40,000, and 0.98
and 1.28 at 60,000. The straight lines through the 40,000 and 60,000 readings cross near 64,500 and
45,600 outputs (interpolating the ratio instead gives about 63,500 and 46,600). Past the crossing
each output adds 1.5 or 3.2 µs to the index read against 1.1 µs to the scan, so the index read
costs more than the scan by a margin that grows with the outputs. A read that passes the first tip
check, walks the index and fails the second (a block landed meanwhile) pays the walk and then the
scan, once each.

Every read, index walk and scan alike, holds one of the gate's six permits from start to end:
`utxos_for_addr20` takes it (`src/api/mod.rs:1927`) and moves it into the blocking closure
(:1933-1934) that runs `utxos_for_addr20_blocking`, which calls `addr_index::read` (:1976). So the
gate bounds these reads as it bounded the scans: six at once fill it and the rest shed with
`SCAN_BUSY` after 250 ms. Residual: the address is the caller's choice, and outputs of value 1 at
fee 0 are valid, so anyone can pay about 46,000 to 65,000 outputs to one address once (about 90 to
130 transactions of 512 outputs) and make that address's reads cost a scan, and more with more
outputs. In those runs, at 60,000 outputs, that address's read took 103 and 136 ms through the index
and 105 and 106 ms through its own scan, the read a node without the index makes for it. Estimated
from these minimum thread CPU times (not from timed concurrent requests, and not a measured point
where shedding starts), six permits serve about 58 or 44 index reads a second and about 57 scans a
second in both runs, so callers at 25 requests a second each fill the gate through the index with 3
or 2 of them, where the scan needs 3. A per-address cache of the answer for one tip would bound
repeated reads of such an address to one a block; it is not built. While the index is not current
(the first start with idx version 3, a failing reconciler) every read costs the scan again.

## Gossip validation

gossipsub runs with `validate_messages`, so a received message is forwarded only after the gossip
arm reports Accept. Upstream runs gossipsub in `ValidationMode::Permissive` without
`validate_messages` (d168f70 `src/net/node.rs:2632-2643`), so every message is forwarded before the
node decodes it, and k altered copies of one message are k ids forwarded across the network. The arm
is a closure that returns a verdict on every path and `report_gossip_verdict` reports it once (rustc
refuses `continue` and `break` inside a closure; a store error reports Ignore before it ends the
loop). Never Reject: it differs from Ignore only in peer scoring, which is off. Accept: a header
that this message newly indexed, or a tx the mempool holds byte for byte afterwards, newly added or
already held (a resubmit's re-gossip has to cross nodes that hold the tx; a txid leaves the
script_sigs out, so "the txid is held" is not enough, `Mempool::holds_encoding`). Ignore: everything
else, including a header already indexed (every header indexed from a headers response is published
again as gossip, so a syncing node publishes its whole catch-up) and a header whose parent is
unknown (its PoW is checked only against its own bits, which can be the PoW limit).

Gossip and request-response decoding refuse trailing bytes (`decode_wire`); upstream decodes gossip
with `allow_trailing_bytes`. Every encoder writes `consensus_bincode()` output and nothing after it,
in upstream v1.0.0, v1.1.1, v1.1.2 and main, and `proto.rs`, `types/` and `codec/` are
byte-identical across those versions and this one, so the refusal refuses nothing an honest node
sends.

Costs: a node relays nothing it cannot index or admit, so while behind the tip it relays only the
txs its stale UTXO set admits and the headers whose parent it has, and its peers take the rest from
another mesh path or from their own tip poll (10 s). A tx refused while something it depends on is
missing here (an input not in the UTXO set, or the proposal of an Attest; the node is behind, or the
dependency is not mined yet) is parked (`src/net/orphan_txs.rs`): at most 256 txs and 512 KiB of
serialized txs, oldest out first, dropped 30 blocks of header height after it was parked. Entries
are keyed by the message's content hash, not the txid, which leaves the script_sigs out: a copy with
a corrupted signature that arrives first does not take the honest copy's place. When the tip moves
(checked on the 5 s poll tick) the node tries the parked txs whose dependencies now exist, copies of
one txid in arrival order; the first admitted removes the rest, a copy refused with nothing missing
leaves, and one refused while a dependency is missing again (a reorg) stays. Each admitted tx is
gossiped, insured as a first accept: the relay step it skipped happens when its view changes, with
no timer (the node has no rebroadcast). A copy the node received sits in gossipsub's duplicate
cache, so that publish waits in PublishRetry, which keeps it while the mempool holds those bytes
(the txid alone leaves the script_sigs out). gossipsub removes an expired id only when it records
another one (`TimeCache::entry`, `time_cache.rs:138-140`; `contains` ignores expiry), so the
publish goes out after the first id recorded past the 60 s window, on a live chain at the latest
the next block's header gossip. Residual: a node that receives no gossip at all past that minute (no
block and no tx anywhere on the network) does not send it. Anyone can fill the set with txs naming
dependencies that do not exist, or with copies of one tx; that pushes out only other parked txs,
which without the set are dropped on arrival. Without it, a tx gossiped while a relay is behind
stops at that relay for good, and so does an Attest whose proposal it does not know yet.

A header ignored for an unknown parent is not announced again when its parent arrives while
gossipsub's duplicate cache holds its id (60 s); an unreported message leaves the cache after 5
heartbeats. The arm reports a header within the same event and a tx when its check returns ("Gossip
budget"); a tx check that returns after gossipsub dropped the message is the one case where the node
publishes the tx itself. A peer that has spent its gossip budget and relays an honest message first
gets it ignored here, and the honest copies are dropped as duplicates for 60 s; at the tip that peer
is disconnected on its first refused message. Upstream nodes still forward everything; nothing on
the wire changes. Pinned by `tests/p2p_live_gossip_tx.rs` (three nodes in a line: six verdicts) and
`gossip_attribution_tests::a_padded_copy_of_an_honest_message_does_not_decode`.

## Gossip control size

gossipsub 0.50 refuses an RPC whose control part (IHAVE, IWANT, GRAFT, PRUNE, subscriptions)
exceeds 16 KiB and closes the stream; the fifth stream on a connection disables gossipsub on that
connection, which can stay open with no gossip on it. Message ids are 64 hex characters, so an
IHAVE of more than 247 ids on the header topic crosses 16 KiB, and every heartbeat sends the peers
outside the mesh one IHAVE listing every id published or forwarded in the last three heartbeats: a
catch-up burst (each header indexed from a headers response is published) or a burst of relayed
transactions would cut a node off from those peers. The node sends at most 200 ids per IHAVE or
IWANT (`MAX_GOSSIP_IDS_PER_CONTROL`, 13,217 bytes on the header topic) and accepts control parts
up to the whole-RPC bound of 256 KiB (`MAX_GOSSIP_CONTROL_BYTES_RECEIVED`), because upstream nodes
(gossipsub 0.47.0) send IHAVEs of up to 5000 ids with no control limit. Pinned in both directions by
`gossip_wire_tests::a_catch_up_burst_keeps_gossip_flowing_to_a_peer_outside_the_mesh`. The receive
bound can return to the 16 KiB default once no peer on the network is measured sending a control
part above 16 KiB ("Dependency internals the code relies on").

## Address book

The book holds at most 128 peers (`MAX_KNOWN_PEERS`), first come, and is saved to `peers.txt`. In
upstream an address leaves it only on a refused, unsupported, invalid-data or wrong-peer dial
(d168f70 `src/net/node.rs:3284-3314`), never on a timeout, so a book filled once with unreachable
addresses stays full and refuses every new peer. Measured on a mainnet node with a full book (128):
in two hours of its journal, 3,815 failed dials, 3,688 of them timeouts
(`Os { code: 110, kind: TimedOut }`) across 116 peers, the most-dialed timing out 185 times (about
every 39 s) and most 15 to 27 times.

Here an address leaves the book after `ADDR_TIMEOUTS_TO_EVICT` (3) timeouts in a row
(`note_addr_timeout`); a connection to it resets the count. Bounds: nothing is counted while the
node holds no connection (a timeout then says more about our own network), a configured bootnode
is never evicted, and removing a peer's last address never takes the book below
`MIN_KNOWN_PEERS_KEPT` (32) peers. One Peers response adds at most `MAX_NEW_PEERS_PER_RESPONSE`
(16) peers new to the book (`parse_peer_strings_into_known_addrs`); the rest is discarded, the
sender is not penalised, and addresses for peers already in the book are still taken. A Peers
response is taken only as the answer to our GetPeers (`Asked::Peers`, at most one every 30 s per
peer); one sent to any other request is dropped unread, as a Tip or Headers answer is ("Peer
score"). Upstream takes a Peers answer to any request (`:4403-4412`), so a peer can answer each
GetTip (every 10 s), headers request or GetBlock with an address list, rewrite `peers.txt` and start
dials with each (`tests/p2p_live_peers_answer.rs`).

An address enters the book only when it is routable (`should_store_discovered_addr`): an
IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is judged by the IPv4 rules, and 0.0.0.0/8 and
240.0.0.0/4 are refused. Upstream's filter (v1.1.2 `src/net/node.rs:644-690`) passes
`/ip6/::ffff:127.0.0.1` where it refuses `/ip4/127.0.0.1`; its dial fails at once (the transport's
IPv6 sockets are v6-only, libp2p-tcp 0.45.0 `lib.rs:203-205`) with an error the eviction does not
count, so such an entry holds its slot for good. A mapped public IPv4 address still passes and
still cannot be dialed; addresses whose dials fail unreachable are not evicted.
`peer_state_tests::mapped_and_reserved_ipv4_addresses_do_not_enter_the_book`.

The per-address dial backoff (30 s, 2, 5, 15 and 30 minutes, then an hour) keeps its failure count
for two hours past the backoff it started (`prune_addr_backoff`); upstream drops the count the
moment the backoff ends (`:781-785`), so the next failure starts again at 30 s and the backoff never
passes its first step (in the measured window above, the most-dialed dead address timed out 185
times). The count is our own failed dials to that address, so no peer moves it.

How a timeout is known (from the sources): the swarm reports a failed dial with each dialed address
and its own error (libp2p-swarm-0.48.0 `DialError::Transport`, `lib.rs:1553`). The TCP transport
connects without a timeout of its own and returns the socket error the kernel reports for that
connect (libp2p-tcp-0.45.0 `lib.rs:396-416`, `provider/tokio.rs:94-98`), which the boxed transport
wraps (libp2p-core-0.44.0 `transport/boxed.rs:173-175`); on a mainnet node it printed as
`Other(Custom { kind: Other, error: Left(Left(Os { code: 110, kind: TimedOut, .. })) })`, and
`timed_out_dial_addrs` takes the addresses whose error text holds `TimedOut`.

Who can make an address leave: only the host at that address, or the path to it, by not answering
our connect. A count is kept per address we dialed, from the swarm's own report, so no message from
any peer moves it, and the removal is of that address only, never of a peer: an attacker that
plants an unreachable address under an honest peer's id loses its planted address, and the peer's
real address stays. Pointing a planted id at an honest peer's real address gives a wrong peer id at
the handshake, not a timeout. A refused, unsupported, invalid-data or wrong-peer dial also removes
only the address that dial used (`forget_failed_dial_addrs`, from the dialed address in
`DialError::WrongPeerId` and the per-address errors of `DialError::Transport`). Upstream removes
every address of the peer on such a failure, and the whole entry on a wrong peer id
(`:3284-3314`), so an address planted under an honest peer's id that answers with another identity
or a closed port erases the honest peer's real address too. What eviction does not stop: the slots
it frees are filled first come, by identify and Peers responses, so a peer that answers many Peers
requests still offers many addresses (16 new per response); the gain is that a book full of dead
addresses no longer refuses every honest peer. Tests: `peer_state_tests` (the live error text and
the typed path, the count, each bound, the per-response cap).

## Peer score

`peer_score` orders sync peers (after chainwork) and the cap and idle evictors (lowest first), and a
score at or below `QUAR_SCORE_THRESHOLD` (-30) quarantines the peer for 5 minutes. Upstream's score
is a saturating sum with no bound and no forgetting (d168f70 `bump_score`,
`src/net/node.rs:2072-2082`): a peer with farmed credit is never quarantined and never cap-evicted
ahead of an honest peer, and a peer out of quarantine stays below the threshold, so its next single
penalty sends it back.

Here, all three together: `bump_score` clamps to [`SCORE_MIN` -90, `SCORE_MAX` +60];
`decay_scores` moves every score one step toward zero each `SCORE_DECAY_EVERY_SECS` (60 s) by
max(1, |s| / 8), from the ceiling six steps to half, and a step never crosses zero; entering or
extending a quarantine resets the score to 0, so the quarantine is the punishment and the score is
what accumulates between quarantines.

From the code: `bump_score` is the only writer of `peer_score` (18 call sites in
`src/net/node.rs`), and every call names the peer whose own traffic caused it: the request-response
peer of the response or request (`peer`), the noise-authenticated forwarder of a gossip message
(`fwd`), a connected peer by its own reported height (`penalize_stale_peers`), or the peer that
served a body (`providers`). The bounds that follow: a peer at the ceiling is quarantined on its
fifteenth SCORE_BAD_INVALID (-6) in a row; while it stays above the threshold, decay forgives at
most 3 points a minute (|s| from 24 to 29), so a peer that earns nothing can sustain at most about
one SCORE_BAD_INVALID every two minutes without quarantine, where with an unbounded sum a peer with
farmed credit can sustain any number.

Credit is paid only for work new to this node: +3 for a block a peer serves in answer to our
request, +12 when that block becomes our tip, and +1 to the forwarder of a gossip header that its
message indexed here. The +1 is not paid for a header already indexed or refused by
`index_header`, since re-gossiping headers we hold would farm score to the ceiling, and the +12 is
not paid merely because `maybe_reorg_to` returned Ok, which it also does when it applies nothing (a
bad mark, a missing body). The +3, with a good block in the quality record, is paid once the body
is new here, binds to its header, passes the store checks (size, repeated txid) and its header
indexes; a body refused at any of those, or one we hold already, earns nothing, so a refusal that
strikes (-6) is not offset by the +3. Paid before those checks, a genuine block answered with its
last tx repeated (the merkle root unchanged, refused at store at no cost) would earn it for every
block we ask for. A body that passes them and fails only when applied (an altered signature) still
earns the +3 and the good block: the block-response path does not run the apply checks, and their
failure blames nobody (`chain::body_fault`). The +60 ceiling bounds the score, not the quality
record, where each good block adds 25 ranking points that persist, so credit farming remains,
limited only by how many blocks we request.

A Tip answer and a Headers answer earn no score. Upstream pays every non-empty Headers answer +2
and its length in the quality record (15 points a header) before any header is checked
(`:3959-3978`), and one answering a GetTip counts like one answering a headers request, so 1,024
copies of a header we hold, every 10 s, farm about +12 a minute and 92,160 quality points. Here a
Headers answer is handled only when it answers our own headers request (`Asked::Headers`; any other
is dropped unread, no score), and the quality column for headers is written as 0 and ranks nothing,
also a count persisted earlier. An honest headers answer is indexed as before; it moves only the
peer's last-seen time. An empty answer costs nothing: in upstream an empty answer from the sync peer
costs it 1 (`SCORE_BAD_EMPTY_HEADERS`, `:3959`), though an honest peer answers empty whenever its
chain has nothing above our locator's anchor, as when it relays a side-branch header whose parent
we lack. Sync does not wait on such a peer: a headers request goes to any peer whose Tip answer
claims more work than ours (20 s cooldown per peer) and to the forwarder of a gossip header whose
parent we lack, never to the sync peer as such. Background requests are in "Background requests"
below.

In upstream a Tip answer naming the zero hash earns +1 at every 10 s poll (`:3836-3842`), so such a
peer sits at 42 against an honest 0 and sustains one SCORE_BAD_INVALID a minute. Here a Tip answer
to our GetTip adds one good tip (5 points in the quality record: the dial, redial and persistence
order) and sets the record's height and work only from the header we indexed for it
(`note_tip_answer`); upstream records the claimed height and work unchecked (`:3827-3828`), and a
`u128::MAX` claim outranks every honest peer. A Tip sent in answer to any other request, or to none,
is dropped unread, as a Headers answer and a Peers answer ("Address book") are: it sets no height or
work and starts no request (`tests/p2p_live_header_credit.rs`). Each answer to each poll counts, so
the good tip count rewards answering, not novelty, but only its first 20 rank
(`TIP_ANSWERS_RANKED`, 100 points), and likewise only 5 dial successes (`DIAL_SUCCESSES_RANKED`, 100
points), a dial success being a connection we dialed (`note_connected`). Upstream caps neither and
counts every first connection, inbound included, as a dial success (`:3243-3246`): an identity that
reconnected to us 300 times in 16 s ranked 7,600, and one that answered our polls for a week with
our own tip 302,400, against 375 for an honest provider of three canonical blocks, in our dials,
our Peers answers and the 512 persisted records (the configured bootnodes, dialed first at every
start, bound the eclipse). Serving blocks decides the order: 25 a served block, 100 a canonical
one, uncapped. A persisted record keeps its counts and is ranked under the same caps.

Only a request timeout costs a peer -20 as a `timeout` (`charges_quality_timeout`); upstream charges
every outbound failure as a timeout (`:4573-4631`), a connection closed by the peer's restart or by
our own disconnect with a request in flight included. A failed dial costs it once, as a dial
failure. Tests: `peer_state_tests::reconnecting_or_staying_connected_does_not_outrank_serving_blocks`,
`peer_state_tests::only_a_request_timeout_is_charged_as_a_timeout`. A peer whose block requests time
out once a minute stays near -1. A peer that stays 12 or more blocks behind (-2 a minute,
`penalize_stale_peers`) settles between -16 and -14 and is not quarantined for it; it stays behind
every peer with more chainwork in the sync order and low in the eviction order.

The clamp, the decay and the reset change how much a score moves, never whose score; no call site
lowers one peer's score for another peer's traffic, so no peer can make an honest peer look like the
attacker through the score. Tests:
`peer_state_tests::a_score_is_bounded_forgets_and_starts_again_after_quarantine` (the farm bound,
quarantine at the ceiling, the reset, an honest peer with a timeout a minute, recovery by decay),
`logging_tests::quarantine_and_ban_report_only_the_transition`,
`peer_state_tests::a_tip_answer_ranks_a_peer_by_the_header_we_indexed`,
`peer_state_tests::a_persisted_header_count_ranks_nothing` and `tests/p2p_live_header_credit.rs`
(a replaying peer earns nothing and its header sent to a GetTip is not indexed; an honest peer's
chain is followed, its score never drops and its served blocks earn it at least 15; the sync peer's
empty answer leaves its score at 0; known and refused gossip headers earn their forwarder nothing
and a new one 1), `body_refetch_tests::a_block_that_does_not_become_canonical_earns_its_provider_nothing`.

## Gossip budget

A forwarder's gossip past `RL_MAX_GOSSIP_MSGS_PER_WINDOW` (1,024) in one `RL_WINDOW` (10 s) is
dropped with an Ignore verdict and the forwarder is kept (`gossip_gate`). Upstream also disconnects
it (d168f70 `src/net/node.rs:3457-3461`), though an honest relay passes on whatever its mesh sends
it: a relay for several busy peers, or one republishing its catch-up, loses the connection at
message 1,025. That disconnect stood for a defence against send-queue growth, which gossipsub
0.50.1's bounded queue now is (`a_peer_that_stops_reading_fills_a_bounded_queue`). A banned or
quarantined forwarder is still disconnected at once while we are caught up, and the drop scores
nobody; a banned peer's connections are also closed at any height, at the next poll tick
("Connection admission").

What the drop does not bound: bandwidth, decoding, signature checks, content hashing and
gossipsub's 60 s duplicate cache are spent on every message before the budget. Measured in a debug
build (one process; two unsigned origins, relay B, receiver A): A indexed the 1,024 of a 1,100 burst
in 0.47 to 0.49 s, and under twice the budget for 30 s it indexed 3,210 of 5,920 (106 to 107 a
second; two runs). A debug build verifies an ed25519 signature in 8.47 ms, so a signed burst from
one node was indexed at about 100 a second (1,100 in 11.1 s) and never reached the budget; release
figures were not measured. Residual: in a window whose budget is spent, the relay's own
announcements are dropped as well, and A learns a new block from its Tip poll (10 s) and the 20 s
headers cooldown: with B's announcement of the block asserted dropped, A applied it 19.8 s after the
announcement while the flood ran (one run), against 0.7 s without a flood. Tests:
`gossip_attribution_tests::over_the_gossip_budget_drops_and_keeps_the_forwarder` (ban and
quarantine still disconnect at the tip), `tests/p2p_live_gossip_rate_limit.rs`.

Gossip txs. A tx's mempool check costs about one spent-output read and one signature check per
input (with the sighash once per tx; upstream's `verify_sig` recomputes it per input, d168f70
`src/crypto/mod.rs:111`), and upstream runs it inline on the p2p loop (`src/net/node.rs:3619`):
copies of a 512-input tx whose last signature is bad, each a new message id, fit the message budget
1,024 times a window, and each holds the loop for its whole check (`tests/sighash_once_cost.rs`,
release, thread CPU time: 70.8 ms with the sighash per input, 21.5 to 26.3 ms with it once per tx).
Here a forwarder is also charged the inputs of its gossip txs that their check did not admit (a
refusal, a conflict with a held tx, a byte-different copy of one); once 4,096 are charged in one
`RL_WINDOW` (`RL_MAX_GOSSIP_TX_INPUTS_PER_WINDOW`, eight full-width refusals), its next txs are
dropped unchecked and nothing is struck. Admitted txs are not charged, so a relay forwarding valid
wide txs is never stopped by it (charging every tx would drop an honest relay's ninth 512-input tx
in a window). A refusal that is parked (an input or its proposal is missing here) is charged like
any other, so while this node catches up, an honest relay past 4,096 refused inputs in a window has
its further txs dropped unchecked, with no strike; what it already sent is held by the orphan pool's
bounds (256 txs, 512 KiB). The budget is read when a tx arrives and charged when its check returns,
so the bound is not eight refusals: a forwarder gets the eight checked plus whatever of its txs are
queued or running when its charge lands, up to the queue's 16 full-width txs and the 2 running, 26
in all. `tests/p2p_live_gossip_tx_checks_off_loop.rs` pins that bound; in one run it counted 20
checks for 64 refusals sent 40 ms apart by one forwarder, and 46 with the charge removed. The total
cost stays capped by the two checks running and the queue; under a flood from many forwarders the
cost is honest gossip txs dropped at this node, not funds and not the p2p loop.

The checks run on the blocking pool, at most two at once (`GOSSIP_TX_CHECKS_IN_FLIGHT`) with at
most 8,192 inputs waiting (`GOSSIP_TX_CHECK_QUEUE_INPUTS`); a tx past that is dropped unchecked,
and the loop reports each verdict when its check returns. A check that returns after gossipsub
dropped the unreported message (5 heartbeats; a slow blocking pool or store, or a long queue, can
take that long) finds nothing to forward: the Accept returns false. Left there, that tx would be
held here and forwarded to nobody. So the node publishes it as a first accept, insured, when the
pool still holds those bytes, as it does a parked tx: the copy it received is in its own 60 s
duplicate cache, so the publish waits in PublishRetry until gossipsub prunes that id (on a live
chain at the latest the next block's header gossip). Gossipsub never forwarded that message.

Validation is not forwarding: an Accept's true says only that gossipsub still held the message;
gossipsub drops `forward_msg`'s answer, false when no peer is a recipient, and any send a full
queue refuses (0.50.1 `behaviour.rs:979-985`, `:3007-3040`). So no Accept retires a queued publish.
A queued tx publish (a late accept's, a submit's, a parked tx's) stands until our own publish of its
bytes is queued to a peer (`publish` returns Ok only then, `:724-737`), by its own retry or by a
late accept's first attempt, which also retires a queued entry of the same bytes
(`PublishRetry::published`), or until the pool no longer holds those bytes. If an Accept of the
same bytes retired it, one that reached nobody (no mesh peer but the copy's sender and author, or
every send queue full) would drop a submit's insured publish or a waiting late accept, and the tx
would stop at this node. The cost is a redundant publish, possible and bounded: when gossipsub
forwards a copy of the bytes while their publish waits, the publish still goes out once our
duplicate cache lets it, about a minute later, and leaves the queue at its first success. A receiver
within its own 60 s window drops it inside gossipsub (`behaviour.rs:1992-1999`; this node enables no
peer scoring, so nothing is charged). Past that window (gossipsub prunes an expired id before it
records one) the publish is new to it. A node on this version checks it: `Mempool::insert_checked`
returns at the held txid before any signature check, the check finds these bytes held, and the node
reports Accept and forwards it once, with no strike and no refusal charge
(`charge_gossip_tx_refusal` runs only for a tx it does not forward). An upstream node (d168f70)
returns at the same place and ignores the result. A node that holds another encoding of the txid
refuses the bytes and charges the forwarder their inputs against its refusal budget, with no
strike, as it does for any copy of them.

A late accept goes out once per tx while the pool holds it (`PublishRetry::claim_late`): were the
receivers' checks of it late too, each would publish it a minute later, and so on while the tx is
held. A late accept is held back while it waits in PublishRetry (`RetryFor::LateTx`) and once it
has gone out, and only then: one the bounded queue evicts before it went out (256 entries, the
oldest tx first) can be queued again by a later late check; a claim that outlived the eviction would
leave the tx unsent while held. A waiting late accept of bytes the pool no longer holds (another
encoding of its txid replaced them) gives way to a late check of the held bytes; refusing that claim
would let the next drain drop it unsent, and the held encoding would have no publish. The guard on
a late accept that has gone out stays per txid: once one encoding's has gone out, a late check of a
replacement publishes nothing while the txid is held. A check runs without the chain lock, as a
`/tx/submit` check does, so a tx checked against the state before a block can be admitted after
that block's prune; the next prune or a template's own check removes it.

Measured on loopback in a debug build: two gossipers each sending 8 copies of a 512-input refusal at
once, GetTip answered within 13.9 ms throughout (40 answers in 4 s); with the checks inline on the
loop the slowest answer took 739.7 ms and 14 were answered. Tests:
`gossip_attribution_tests::refused_gossip_txs_are_charged_by_inputs_and_dropped_past_the_budget_without_a_strike`,
`tests/p2p_live_gossip_tx_checks_off_loop.rs` (also: nine valid 512-input txs from one relay in a
window are all admitted; a tx checked 15 s late reaches the next node at 66.9 s, through the node's
own publish, and one checked at once is forwarded once; a tx checked 15 s late whose later copy from
the node's only peer is accepted at 62 s, forwarding to nobody, reaches a node that connects
afterwards at 126.9 s from the node's own publish and not again by 208 s, and a submitted tx whose
gossip copy is accepted while cached, forwarding to nobody, reaches such a node at 66.9 s),
`publish_retry_tests::a_tx_whose_check_returned_late_is_published_once_while_held` and
`::a_late_accept_evicted_from_the_queue_before_it_went_out_can_be_queued_again` and
`::a_late_accept_of_a_replaced_encoding_gives_way_to_one_of_the_held_encoding` and
`::our_own_publish_of_queued_bytes_retires_their_entry`, and
`tests/p2p_live_gossip_tx.rs` (a relay forwards a gossip tx only when it admits it).

## Background requests

GetTip, GetHeadersByLocator and GetPeers go through one scheduler, `src/net/background.rs`. Each
peer is owed: a GetTip 10 s after its last (at first sight for a new peer, at once while our tip is
stale); a headers request once its Tip answer to our GetTip claims more work than ours or it
forwards a gossip header whose parent we lack, due when owed or at the end of its 20 s headers
cooldown, whichever is later; a peers request on connect and on each identify exchange, at most
every 30 s, due when owed. Demand is kept until sent or until the peer disconnects. A peer has at
most one request in flight, and its next is its earliest due kind (ties: tip, headers, peers). At
most `CEILING` (16) are in flight in all, and free places go first to the peer that has waited
longest since its last request (since it was first seen, for a new one), one per peer.
`pump_background` runs this at each 5 s poll tick, on connect, when demand is recorded and when a
non-Tip answer or a failure frees a slot. Block requests have their own budget (`inflight`).

Why the ceiling: an answer is read up to the wire limit (`MAX_RR_MSG_BYTES`, 1 MiB) before it is
checked, and admission takes up to the connection cap plus `PEER_CAP_BURST` (64): 96 peers by
default, 128 on a bootnode, more under `CSD_MAX_PEERS`. One request per peer would allow 96 to
128 MiB of answers in flight; 16 allows 16 MiB. Upstream shares `MAX_BACKGROUND_OUTBOUND_RR` (8,
d168f70 `src/net/node.rs:130`, commented "reserve remaining slots for headers/blocks") between the
kinds with no per-peer limit and no kept demand. Simpler schedules starve: more peers than slots;
eight peers replacing headers requests; four peers holding the headers share; four peers
reconnecting every 10 s; within one peer, a GetTip answered in 10.1 s starving its peers request,
and refreshed headers demand starving its tip polls.

Bounds, with T = 5 s (scheduler runs come at least that often: each tick, and on connect, recorded
demand and freed slots), r a peer's answer time, n the kinds it is owed (at most 3), and R the
longest any peer holds a request (the transport fails it at about 25 s: a 10 s stream upgrade, then
the 15 s request timeout; an unreported request frees its peer at 60 s):
- Across peers, counted over all k contenders: every peer holding an outstanding request,
  eligible or not (a quarantined peer leaves the eligible set but keeps its slot until its request
  settles), and every eligible peer that can fall due in the wait; each holds at most one request.
  With k at most 16 a place is always free, and a request is admitted at the next scheduler run, at
  most T later (W = 0 beyond that T); with more, a peer free with a request due is admitted within
  W = ceil(k / 16) x (R + T) of wall-clock time, since places go to the peer that has waited longest
  and each frees within R and is refilled within T. Counting only peers with a request due is wrong:
  16 peers holding 9 s requests and a 17th connecting at 1 s give k = 1 and W = 0, and the newcomer
  waited 8.1 s (within ceil(17 / 16) x 14 s); counting only eligible peers is wrong too: with one of
  those 16 quarantined, 16 are eligible and the newcomer still waits 8.1 s, its contenders being 17.
  21 peers answering promptly: W at most 2 x 5.1 s; 96 peers each holding to 25 s: W = 6 x 30 s =
  180 s.
- Within a peer: a kind is sent within n x (r + T + W) of its effective due time, which is a
  tip's 10 s after the last, headers' max(owed, last headers + 20 s), peers' owed time; so a kind
  of period P (tip 10 s, headers 20 s while owed again, peers 30 s while owed at each identify) is
  sent at most P + n x (r + T + W) after its previous one. Measuring a newly owed headers request
  from its demand is wrong: headers answered in 0.1 s and owed again at once are due only at 20 s
  (sent at 20.1 s, within 2 x 5.1 s of it). Test schedules: answers in 10.1 s with peers owed, tip
  gap at most 40.2 s, the peers request delivered; answers in 14 s with headers owed, tip at most
  48 s, headers 58 s; answers in 20.1 s with headers owed again each time, tip at most 60.2 s. In
  the 96-peer case with all three kinds owed, the honest peer waited at most 150 s for a place
  (deadline 180 s), got a request every 150 s, and each kind every 450 s (bound P + 3 x 185.1 s).

Tests: `net::background::tests` (each schedule, measured from the previous request of the same
kind or from the effective due time; a fixed priority between kinds, no ceiling, a peer-id order,
and a count of only due or only eligible contenders each fail them) and
`tests/p2p_live_far_behind_sync.rs` (a fresh node syncs 1,100 blocks from one peer and its peers
request reaches the peer: 145.5 s in one run).

Residuals and possible changes:
- Not built: a response limit per request kind on the request-response codec, which libp2p clones
  per outbound exchange (`write_request` before `read_response`; a reading of the pinned
  source): a Tip is 60 bytes encoded and a full headers answer 86,028 bytes, so the 1 MiB read limit
  is needed only for blocks; GetPeers and error answers need their own limits first.
- The 16 MiB figure counts raw wire length, not allocator capacity, decoded objects or block
  responses (`read_response`, `src/net/node.rs`). Inbound requests are bounded on their own: each
  is read only up to its kind's largest encoding (`request_limit`: 4 bytes for GetTip, 20 for
  GetHeaders, 4,116 for a 128-hash locator, 36 for GetBlock, 100,004 for SubmitTx, 6 for GetPeers),
  the kind read first, so a connection's four streams hold at most 400,016 bytes of requests;
  upstream reads each up to the wire limit whatever its kind (d168f70 `src/net/node.rs:1276-1297`).
  No honest request is larger: upstream sends GetTip, GetPeers, GetBlock and a locator of at most 65
  hashes (`build_locator`, v1.0.0 to main d168f70; 2,100 bytes), never GetHeaders or SubmitTx. A
  request over its kind's limit fails before the request-response layer registers it and is only
  traced ("Block-request failures"). Tests:
  `sync_transport_cap_tests::a_request_is_read_only_up_to_its_kinds_largest_encoding`,
  `sync_transport_cap_tests::the_largest_request_of_every_kind_is_read`.
- The immediate block request on a new child header checks the per-peer limit but not
  `MAX_INFLIGHT_BLOCKS`, so nine peers each announcing a child can put nine in flight.
- A requested body that binds and stores but fails at apply earns +3 and a good block ("Peer
  score").
- The idle evictor removes unresponsive peers only: every Tip answer to our GetTip, which every
  connected peer is asked each 10 s, refreshes `last_useful_peer_at`, so a peer that answers only
  our polls is never idle, and a requested body refused later, which refreshes it first, changes
  nothing. Such a peer is bounded by the cap evictor, not the idle one.

## Connection admission

Upstream bounds peers, not connections: its connect arm counts a peer's first connection and lets
any further one through uncounted, and ignores a banned peer's new connection without closing or
counting it (d168f70 `src/net/node.rs:3195-3229`), and its transport has no handshake deadline. So
one PeerId can hold any number of connections, each with its four request streams; a TCP connection
that never sends a byte is held until the remote closes it, and a dial to an address that accepts
TCP and never answers never fails, so idle connections can take the node's descriptors and its RPC
listener with them (a node driven to its descriptor limit this way failed `/health`) and a tarpit
can pin the 128 pending dials; and a banned peer keeps an uncounted connection, served once its ban
is pruned. Here (`src/net/admission.rs`):

- A connection's handshake (TCP connect, protocol negotiation, noise, yamux) must finish within 20 s,
  inbound and outbound (`HANDSHAKE_TIMEOUT`; libp2p-core's `Multiplexed::timeout`, which wraps the
  dial and the listener upgrade alike). Upstream sets none; its handshake with us takes a few round
  trips, and 20 s is twice libp2p's own builder default and leaves room for four lost SYNs. A dial
  that ends at the deadline counts as a timeout toward the address book's eviction ("Address book";
  `dial_error_text_is_timeout` reads libp2p-core's `TransportTimeoutError::Timeout`), so a dead
  address leaves after three 20 s dials instead of waiting on the kernel's connect timeout.
- At most 2 established connections per peer, both directions together
  (`MAX_ESTABLISHED_PER_PEER`, `ConnectionCaps`). Upstream dials every address it holds of a peer it
  is not connected to, with no peer condition (`swarm.dial(addr)`, libp2p-swarm 0.45.1
  `dial_opts.rs:163-166`, `:305-308`; d168f70 `src/net/node.rs:3074-3110`), and at its start the
  same address twice when it is a configured bootnode and in its book (the bootnode dial and the
  startup dial of its best known peers, `:2708-2766`). So an upstream node opens at most two
  connections at once to a node with one public address; a dial of ours to it at that moment makes
  a third, and the third to complete its handshake, ours or its, is refused while the two stay.
  Harmless to the peer: upstream's refcount reads the refused one as a connection that opened and
  closed (`:3195-3206`, `:3329-3336`), not as a failed dial, and it does not redial a peer it is
  connected to (`:3074-3110`). The cost, if any, is ours: a request it sends on the refused
  connection in the round trip before our close (request-response 0.27.0 spreads requests over a
  peer's connections by request id, `lib.rs:548`) fails as ConnectionClosed, which its
  OutboundFailure arm charges to us (`:4573-4631`: a timeout in its quality record, -1 to our score
  and a 120 s bad stamp for a GetBlock); and when the refused one is our dial, the peer stays
  connected inbound, outside the evictor's protection of the peers we dialed. A dial of ours refused
  by our own limits blames nobody (`dial_refused_by_us`: no dial failure, backoff or forgotten
  address; its pending-dial entry is dropped, `forget_refused_dial`). Residual: a peer whose two
  connections went dead without a FIN or a reset is refused a third until the kernel or the remote's
  reset closes them, at the latest one retransmission timeout (up to 120 s) after it is reachable
  again.
- At most the peer cap plus `PEER_CAP_BURST` established inbound connections (`inbound_cap`: 96 by
  default, 112 with `CSD_MAX_PEERS=48`, 128 on a bootnode): the count at which the connect arm drops
  a new peer, as upstream's does (`:3212-3229`). The cap counts connections and the peer cap's
  evictor counts peers, so with the evictor alone peers holding two inbound connections each keep
  the cap full: on a default bootnode 64 identities, from 16 addresses under the per-address cap,
  fill its 128 places at the peer cap's count, where nothing is evicted, and an honest connection is
  refused for as long as they stay. So the poll tick keeps `INBOUND_RESERVE` (32) places free: past
  the cap less 32 (64 by default, 80 with `CSD_MAX_PEERS=48`, 96 on a bootnode) established inbound
  connections, not counting those already closing, it sheds second inbound connections, the newer of
  a peer's two, never a peer's only one, in the evictor's order and under its protections: never a
  peer younger than `PROTECT_NEW_PEER_SECS` (60 s) or one we dialed unless it is banned or
  quarantined (`maybe_shed_second_inbound`; the order and its protections, shared with the peer
  cap's evictor, `peer_state_tests::the_cap_eviction_order_keeps_young_and_dialed_peers_out`). Whole
  peers are not shed for connection pressure: once the second connections are gone only peers
  holding one are left, and the peer cap's evictor sheds those past the cap, which it does first in
  the same tick. An honest node passes the reserve only with more than 32 of its peers holding two
  inbound connections at once (the shed needs more inbound connections than the peer cap plus 32,
  the inbound cap less 32); a second connection of an honest upstream node shed this way fails the
  requests in flight on it as ConnectionClosed, which its OutboundFailure arm charges to us (d168f70
  `:4573-4631`), and it keeps its first. Our own requests in flight on it are requeued and blame
  nobody ("Block-request failures"). Residual: a peer younger than 60 s is protected, so a flood that
  renews its identities within the minute holds the places as long as it renews them, as it does
  under the peer cap; and an identity whose second connection was shed can open it again and compete
  for the freed places until the next tick sheds it. `tests/p2p_live_inbound_saturation.rs`: 64
  identities with two connections each fill a default bootnode, an honest connection is refused
  while they are protected and admitted and served after, with 96 flood connections left and every
  identity holding one; without the shed, 128 were held at 68 s and the honest connection refused.
  Inbound only: a cap on both directions together would let connections a remote opened fill it and
  refuse our own dials, the peers the evictor protects against being surrounded. Our dials are
  bounded by the dial loops, which stop at the peer cap. `tests/p2p_live_inbound_flood.rs`: with the
  cap at 65, 33 identities fill it with two connections each while the node's dial to its bootnode
  is held by a proxy, and the dial is kept; under a shared cap it was refused.
- At most 8 established inbound connections from one address, an IPv6 /64 counted as one, but not
  from 127.0.0.1 and ::1, so nodes on one host can connect to each other freely
  (`MAX_ESTABLISHED_INBOUND_PER_IP`, `InboundPerAddress`): an upstream node holds at most 2
  connections to us, so 8 admits four nodes behind one address; on a mainnet node the most
  connections one remote address held was three. Another loopback address only comes from a process
  on this host that chose it, and counts like any address. Without the cap, one address holds as
  many connections as it can make identities, up to the node's whole budget.
  `one_address_holds_at_most_eight_inbound_connections_and_loopback_is_exempt` (nine identities from
  127.0.0.2 hold eight, twelve from 127.0.0.1 hold twelve). Residual: the loopback exemption covers
  only this per-address cap. A node that dials another on 127.0.0.1 arrives inbound there and counts
  toward its inbound cap: an inbound flood of identities younger than `PROTECT_NEW_PEER_SECS` (60 s,
  which the evictor keeps, shedding older inbound peers instead, the local link among them when the
  flood is large enough) can refuse the local node's redial until a slot frees, and the other side's
  own redial of it, when it is a configured bootnode, waits as well, since the outbound floor does
  not dial at the connection cap ("Outbound floor"). Upstream's connect arm, with the same figure
  counted in peers, drops that redial the same way. A possible change: exempt configured PeerIds
  from the limits (`ConnectionCaps`) and from the evictor.
- At most 1,024 inbound connections in their handshake (`MAX_PENDING_INBOUND`, a sixty-fourth of a
  65,536-descriptor limit), and 16 from one address, an IPv6 /64 counted as one
  (`MAX_PENDING_INBOUND_PER_IP`, `InboundPerAddress`): one upstream node dials at most every address
  it holds of ours in one pass (`MAX_ADDRS_PER_PEER`, 8) and one more as a bootnode, so 16 admits it
  with room for a second node behind the same address. An idle connection then holds its slot for at
  most the 20 s deadline. Residual: 64 addresses holding their 16 handshakes each keep every other
  inbound connection out for as long as they renew them (each idle connection costs its sender a
  socket and lasts 20 s); our own dials, and the peers already connected, are not touched.
- A banned peer's new connection is closed at connect, and the poll tick closes every connection of
  a banned peer (`banned_with_connections`), at any height: a banned peer is already served nothing,
  and its connection only holds a slot. The ban's entry is kept while the peer holds any connection,
  counted or not, so it cannot lapse first, and a banned bootnode is not redialed until its ban ends.
  If only the gossip gate disconnected a banned forwarder, and only at the tip ("Gossip budget"), a
  node behind its peers would not shed them. A ban comes only from 32 invalid messages in a window
  (`note_invalid`), which an honest peer does not send unless our clock is hours off its own (a
  header past our drift bound fails `index_header`); a request flood is throttled, never banned
  ("Outbound pacing"), and the invalid-tx penalty stays tip-only. Every `note_invalid` call also
  strikes the peer's score by 6 or more, and quarantine at -30 drops the peer's messages for 5
  minutes, so a peer that earns no credit in the window is quarantined before its 32nd invalid
  message counts (at its 5th strike from 0 and its 15th from the +60 ceiling, or one later if the
  minute's score decay, at most 3 points toward zero, falls among them), and quarantine is what
  holds its flood. The ban, with its closes, is the backstop for a peer that keeps earning credit
  while it sends them, for example our sync peer serving blocks that become our tip (+3 when the
  body is stored new, `SCORE_GOOD_BLOCK`, and +12 when the block becomes the tip,
  `SCORE_GOOD_CANONICAL_BLOCK`): from the +60 ceiling, seven such blocks interleaved with the strikes
  can hold it above -30 through 32 invalid messages (32 x -6 = 192 against 89 points of room and 7 x
  15 = 105 of credit; with six it is quarantined at its 30th), and it is banned at the 32nd. The
  early quarantine holds between messages, not within one: quarantine is checked once, when a
  message arrives (the request-response arm drops a banned or quarantined peer's messages before it
  handles them), and the Headers arm runs through a whole answer, striking the peer for each invalid
  header without checking again. So one answer of 32 invalid headers to our own headers request bans
  a peer from score 0, its 5th strike quarantining it on the way, and the next poll tick closes it;
  31 quarantine it and the connection stays
  (`p2p_live_connection_admission::one_answer_of_32_invalid_headers_bans_a_peer_from_score_zero_and_31_do_not`).
  An honest server sends no invalid header unless our clock is hours off its own, as above.
- Inbound refusals and failed handshakes, and dials refused by our limits, log one line per kind at
  powers of two (`log_due`), since they come at the rate a remote opens connections.
- The per-peer, inbound and handshake counts are our own (`ConnectionCaps`), counted as
  libp2p-connection-limits 0.7.0 counts them, and a peer's entry goes with its last connection. The
  crate removes a closed connection from its peer's set and never the empty set (`lib.rs:353-356`,
  made at `:373-376`), so connecting and leaving with fresh identities, under every concurrent limit,
  grows its map for good. `tests/admission_identity_churn.rs`: after 20,000 fresh identities
  connected and left, the crate held 5,250,560 bytes more heap and `ConnectionCaps` none (a counting
  allocator).
- The admission behaviours are the first fields of the composed `Behaviour`. The derive calls each
  field's `handle_established_*` in order and stops at the first refusal (libp2p-swarm-derive 0.36.0
  `lib.rs:290-310`), and a field placed before them records a connection they then refuse:
  request-response 0.30.0 keeps such a connection for good (`lib.rs:757`; it handles no
  `ListenFailure`, `:836-847`), routes requests to it that are never sent (`:575`), and in a debug
  build asserts it away when the peer's last real connection closes (`:678`), ending the p2p task.
  `a_refused_third_connection_leaves_no_record_in_the_behaviours` and
  `a_reconnecting_identity_gets_every_request_after_a_refused_connection` are red with the admission
  behaviours placed last.

Tests: `tests/p2p_live_connection_admission.rs` (on loopback: three connections from one identity
hold two and count as one peer; sixteen idle connections from one address are cut at 20 s, a
seventeenth is refused at once while a peer from another address completes its handshake, and the
address is admitted again afterwards; a dial to a tarpit fails at 20 s; a request flood is throttled
for its window and the peer kept, beside an honest peer), `admission::tests` (the per-address count,
freed when a handshake ends either way),
`peer_state_tests::a_dial_past_our_handshake_deadline_reads_as_a_timeout`,
`peer_state_tests::a_ban_is_kept_while_the_peer_holds_a_connection_and_its_connections_are_closed`,
`peer_state_tests::a_dial_our_limits_refused_blames_nobody`.

## Outbound floor

After the 180 s cold start, the poll tick redials the configured bootnodes while the node is short
of peers. Upstream's short is fewer than `MIN_OUTBOUND_PEERS` (8) connections of any kind (d168f70
`src/net/node.rs:2874-2881`), so peers connecting to us, an attacker's included, stop our own dials.
A mainnet node with 16 connections, 7 of them dialed by itself, made no bootnode redial.

Here `bootnode_redial_due` also redials while fewer than 8 connections are ones we dialed, as long
as the node is under its connection cap. The cap is the limit because a connection past it makes
`maybe_evict_excess_peers` shed inbound peers down to its target (several for one dial); upstream's
trigger (fewer than 8 connections of any kind) still dials at any count. Residual: at the cap,
inbound peers can keep the dialed count under 8; the sign to look for is `/node/info`
`inbound_peers` at or near the cap with `outbound_peers` under 8. The change dials only configured
bootnodes and evicts and scores nobody. Test:
`peer_state_tests::inbound_peers_do_not_stop_the_bootnode_redial`.

## `/tx/submit` under a flood

`/tx/submit` checks a tx (`Mempool::insert_checked`: every input's spent output and signature) on
the blocking pool, at most two at once (`SUBMIT_PERMITS`, `src/api/mod.rs`), and a submit waits for
a permit with no deadline and no waiter cap of its own: at the node a submit is queued, never
refused. End to end that is not the whole answer. A 512-input tx refused at its last signature costs
about 21 ms of check in release (`tests/sighash_once_cost.rs` prints it: 20.8 to 21.1 ms in three
runs), so the two permits clear about 95 such refusals a second per node. A wide tx that spends the
sender's own coins and pays out one unit more than they hold is refused only after every signature
(`outputs exceed inputs`) and leaves nothing stored, so the same tx can be sent again and again. A
flood of them above that rate keeps the queue full: an honest submit waits behind it and can time
out at its caller's deadline, and a reverse proxy that fails a timed-out request over to another
node moves the flood's requests there as well. A caller that hangs up leaves the queue with its tx
unchecked.

Upstream runs the check inline in the async handler (d168f70 `src/api/mod.rs:2577`) and recomputes
the sighash for every input, so wide refusals hold the runtime workers that serve every route and
the same flood stalls every RPC handler. A node behind a reverse proxy sees no client address to be
fair between: fairness between sources belongs at the proxy.

## Duplicate-submit re-gossip

A `/tx/submit` of a tx the mempool already holds re-gossips the held tx (`tx_submit`), so a tx that
stopped at this node can be sent on by submitting it again. There is no per-txid cooldown:
gossipsub refuses to publish an id still in its duplicate cache (libp2p-gossipsub-0.50.1
`behaviour.rs:658-666`, 60 s), so a repeat inside 60 s already costs only a hash lookup, and a
cooldown shorter than that changes nothing; a longer one would delay that resend. The re-gossip
publishes the held tx's own bytes, not the submitted copy, so a POST cannot mint new gossip ids,
and peers forward it only when they hold the same bytes ("Gossip validation" above). What remains:
one mesh broadcast of a held tx per 60 s per caller who keeps posting it. Worth revisiting if
`[tx_submit] DUPLICATE ... re-gossiped` lines in the node's journal exceed about one a second, or a
held tx is seen re-broadcast from one source more often than once a minute.

## Block time on a parent stamped ahead

Consensus admits a header stamped up to `MAX_FUTURE_DRIFT_SECS` (7,200 s) past the receiver's
clock, and a child at once as long as its stamp is at least the parent's plus
`MIN_BLOCK_SPACING_SECS` and above the median of the last 11 (`index_header`). Upstream's miner
waits until the wall clock passes parent.time + 60 before it builds a template (d168f70
`src/chain/mine.rs:186-205`), and only then starts the stale-tip watcher, so one block stamped near
the limit idles every miner on that code for up to about two hours.

This miner stamps `max(now, min_ok)` at once whenever min_ok is at most now + 7,200 - 600 s
(`miner_block_time`, `MINER_CLOCK_SKEW_MARGIN_SECS`), and waits only for a parent stamped later
than that, at most 660 s for a parent at the limit. The margin is the clock skew it tolerates: a
receiver refuses a header only past its own now + 7,200, and the time between our stamp and its
check only advances its clock, so a receiver up to 600 s behind accepts every stamp. That assumes
every receiver's clock is within 600 s of the miner's (an NTP-synced host). A receiver further
behind refuses such a header, and an upstream node strikes the peer that served it in a headers or
block answer (`note_invalid` and `SCORE_BAD_INVALID`, upstream d168f70 `src/net/node.rs:4027-4029`,
`:4321-4323`; a gossiped header that fails is only not indexed). The stale-tip watcher runs from
before the time is chosen, so a wait ends when the tip moves. The rule is the miner's choice inside
the consensus bounds; no node refuses or accepts anything differently.

The cost is in difficulty. While the chain is ahead of the clock the children carry stamps of
parent + 60, so LWMA (45 blocks, 120 s target, solvetimes clamped to [1, 1,440] s) reads 60 s
solvetimes and raises the difficulty until the stamps follow the clock again. Simulated through
the consensus retarget (`tests/miner_future_parent_lwma.rs`: deterministic expected solve times, 60
blocks at 120 s, one block stamped 7,000 s ahead, then 300 blocks):

| Hashrate on this rule | First child after the attack block | Stamps follow the clock from | Highest difficulty | 300 blocks took |
|---|---|---|---|---|
| all of it | 541 s | block 60 | 2.97x | 42,522 s |
| 11% (the rest on upstream's rule) | 1,195 s | block 11 | 1.01x | 41,899 s |
| none (upstream's rule) | 7,141 s | block 2 | 1.01x | 41,916 s |

With part of the hashrate on this rule, that part produces blocks during the window that otherwise
stalls every miner, with no measurable difficulty rise; miners on upstream's rule still wait until
the clock passes the tip, which only a change to upstream's miner removes. With every miner on this
rule there is no stall, and the difficulty rises to about three times the baseline for about 60
blocks before it returns to it. Tests: `chain::mine::block_time_tests`,
`tests/mine_one_rebases_on_tip_change.rs` (a block built at once on a parent stamped 6,500 s ahead;
the watcher ends the wait on a parent stamped 7,000 s ahead), `tests/miner_future_parent_lwma.rs`.

## Transport cap and blocks above 1 MiB

A request-response message of 1 MiB or more is refused on read and on write
(`MAX_RR_MSG_BYTES`), the cap upstream has (v1.1.2 `src/net/node.rs:48`, unchanged at main
`d168f70`). Consensus admits a block up to `MAX_BLOCK_BYTES` (2 MiB), and upstream's unmodified
miner fills a template with up to 500 mempool txs and up to 2 MiB less 16 KiB (main `d168f70`
`src/cli/main.rs:1360`, `src/chain/mine.rs:29` and `:230`, with no transport belt). So valid
pending txs averaging above about 2.1 KB (1 MiB over 500: wide spends such as consolidations, or
a cheap flood of them at the floor feerate) make it mine a valid block between the two, and so can
any miner with a padded coinbase script_sig, which nothing bounds. No upstream node can fetch or
serve such a block. A node with a larger cap could serve one, but on a network whose other nodes
keep 1 MiB it would sit on the other side of the split such a block makes: it would follow a chain
those nodes cannot download, while their miners' gates stay shut on its advertised header. So this
version keeps upstream's cap, and every node refuses the same messages.

What fits: the largest message of each other kind (a full headers answer is 86,028 bytes; a peers
answer is at most 64 peers with 8 addresses each; a tx at most `MAX_TX_BYTES`), and this miner's
blocks, whose templates stay at most `template_byte_cap` (1 MiB less 32 KiB, `src/chain/mine.rs`).
What does not: any block above the cap, legitimate ones included, such as an upstream miner's block
over wide valid txs. The largest mainnet block of heights 0 to 133,044 (all 133,045, read from a
mainnet node; exact consensus size, every txid checked) is 262,307 bytes, at height 116,785,
786,269 bytes short of 1 MiB; the next are 206,121 (height 28,178), 188,494 (117,539), 175,320
(30,646) and 160,585 (50,584). That is the load so far, not a bound on what a miner can produce. A
block request whose answer is refused for its size is handled as any failed request. There is no
line of its own for it: a server on this version or upstream's refuses to write such an answer, so
the requester sees the stream end, not the size. The signal is the tip: while such a block's header
is the heaviest we know, our tip stays at its parent (the body cannot be fetched and our miner's
gate stays shut), which an operator's alert on a tip height unchanged for a long time reports.
Residual: a valid block above 1 MiB, which an upstream miner makes from wide valid txs with no
attack on its code, can be fetched by no node on the network, and while a peer that holds one
advertises it, every miner, on this version or upstream's, counts work it cannot fetch
(`best_peer_work`) and its gate stays shut. Closing it needs a consensus change on every node
together: bound blocks to the transport, or the transport to blocks. Tests:
`sync_transport_cap_tests`, `template_tests::template_byte_cap_is_belted_below_the_transport_cap`,
and `tests/consensus_accepts_a_block_above_the_transport_cap.rs` (17 valid 512-input spends, a
1,245,824-byte block: the header and body rules accept it, the codec refuses it on read and on
write).

## The `/tx/:id` and `/proof/tx/:txid` outcome contract

Both endpoints resolve a txid against the canonical chain (`state::tx_scan::locate_tx`): through
the txid index while its completeness marker equals the tip, and otherwise by a walk back from the
tip (`find_tx_in_chain`). Upstream answers every termination of its walk (scan budget exhausted,
missing block body, undecodable body, genesis reached) with HTTP 200 and `ok:false`, on `/tx/:id`
with one identical `{err:"not found"}`, so a miss proves nothing. Here the outcome is explicit on the
wire (`scan_unavailable` and the two handlers in `src/api/mod.rs`):

| Outcome | Meaning | HTTP status | Body markers |
|---|---|---|---|
| Found | tx located in a canonical block | 200 | `ok:true` and the same fields as upstream's answer |
| Absent | absence proved over the whole chain (the walk reached a block whose `prev` is the zero hash, or the txid index, current at the tip, has no entry) | 200 | `ok:false`, upstream's not-found text (`err:"not found"` on `/tx/:id`, `error:"tx not found in main chain"` on `/proof/tx/:txid`), plus `"complete":true` and `"scanned":N` (blocks the answer covers) |
| Horizon | scan budget exhausted before genesis; absence not proved | 503 + `Retry-After: 30` | `ok:false`, `"code":"SCAN_HORIZON"`, `scanned`, `stopped_at_height` (first height not examined), `retry_after_secs` |
| Incomplete | the walk could not continue at block `at`; absence not proved | 503 + `Retry-After: 30` | `ok:false`, `"code":"SCAN_INCOMPLETE"` (missing body, traversal loop, height underflow, no tip, no header index for the tip) or `"SCAN_DECODE"` (body present, decode failed), `at`, `why`, `retry_after_secs` |
| Shed | the lookup gate (32 permits) had no permit within 250 ms, or the blocking task failed | 503 + `Retry-After: 2` | `ok:false`, `"code":"SCAN_BUSY"` or `"SCAN_TASK_FAILED"`, `retry_after_secs` |

Rules a client can rely on:
- HTTP 200 with `ok:false` and `"complete":true` is the only proved absence. A 200 miss without
  `complete:true` (an upstream node's, or the answer to a txid that does not parse) proves nothing.
- Horizon, Incomplete and Shed are 503, not 404 and not a 200 with a new field: a client that treats
  any non-2xx answer other than 404 as transient fails closed on them, so a node with this contract
  cannot make such a client treat an unproved miss as an absence, where a 404 or a 200 that such a
  client does not know to check would.
- A Found answer has upstream's fields; Absent only adds `complete` (and on `/tx/:id`, `scanned`,
  which upstream's `/proof/tx/:txid` miss already carries). `TxResp` skips both when unset, so no
  existing field changed name, type or position. A Found answer from the index carries the same
  `scanned` on `/proof/tx/:txid` as a walk would (tip height less the tx's height, plus one).
- An index hit is trusted only after it is checked against the canonical height entry and the block
  body (`verify_locator`); otherwise the lookup walks. An index miss is an absence only while the
  marker and the tip both still equal the tip read at entry (`resolve_via_index`), so a tx applied
  in a block that lands during the call is found by the walk instead.
- The walk's budget is `max(max_back, tip height + 1)` (`TX_SCAN_MAX_BACK`, 100,000, is the API's
  `max_back`), so on a consistent chain it reaches genesis and answers Found, Absent or Incomplete;
  Horizon stays in the contract for callers of `find_tx_in_chain` with a budget below the chain.

The outcome classification is pinned by `tests/tx_scan_horizon.rs`
(`scan_to_genesis_proves_absence`, `missing_block_body_is_incomplete_not_absent`,
`every_incomplete_reason_is_reported_as_not_proved`, `stale_index_marker_falls_back_to_scan`,
`fresh_index_miss_does_not_lie_when_tip_advances_midcall`) and
`tx_scan::tests::absent_tx_is_proved_absent_not_horizon_past_max_back`. No test asserts the HTTP
status, header or body mapping.

## Dependency internals the code relies on

This version pins `libp2p =0.57.0` (upstream main: `0.54`, which resolves libp2p-gossipsub 0.47.0),
which takes libp2p-gossipsub 0.50.1 from the registry. 0.50.1 carries the fixes for
GHSA-gc42-3jg7-rxr2, GHSA-xqmp-fxgv-xvq5 and GHSA-g3g5-x568-qvqx (in since 0.49.5) and for
GHSA-vrx6-jcp8-vm7m, a PRUNE for a topic not in the mesh skipped, the whole source diff from 0.50.0
(0.50.1 `behaviour.rs:1767-1775`); the PRUNE and GRAFT behaviour is upstream gossipsub's to keep, and
`the_gossipsub_behaviour_we_rely_on_is_pinned_to_the_locked_version` makes the next gossipsub bump
re-read it. The `dns` feature, which upstream enables, is not: neither version's transport has a DNS
layer (TCP, noise, yamux; d168f70 `src/net/node.rs:2626-2629`).

A bump of any crate below re-reads the cited lines and updates the code and this list together. Two
tests fail when a locked version moves:
`block_request_failure_tests::the_stream_refusal_text_is_pinned_to_the_locked_request_response_version`
and `gossip_attribution_tests::the_gossipsub_behaviour_we_rely_on_is_pinned_to_the_locked_version`.
`tests/p2p_live_gossip_tx.rs` fails when gossipsub forwards a message it was not told to, or holds
one it was told to forward.

- libp2p-request-response 0.30.0 `handler.rs:200-209`: the outbound refusal at the stream limit is
  `io::Error::other("max sub-streams reached")` (`:208`), reported as `OutboundFailure::Io`
  (`lib.rs:969-980`). `is_local_stream_refusal` (`src/net/node.rs`) matches that text exactly to
  tell our own limit from a peer fault ("Block-request failures"); a changed text makes the refusal
  blame the peer. From 0.30 the `Codec` trait is no longer `async_trait` (`codec.rs:38-74`).
- libp2p-request-response 0.30.0 `lib.rs:444-472`, `:523-544`, `:658-733`, `:849-985`: every
  request of ours is reported once, as an answer or an OutboundFailure, and a closed connection's
  requests stop being pending (`is_pending_outbound`) at its close, where their failures are queued.
  `Unreported` (`src/net/unreported.rs`) relies on both to keep a connection we shed counted as shed
  until those failures reach the loop (`net::unreported::tests`,
  `p2p_live_inbound_saturation::a_shed_connection_is_remembered_until_its_failures_are_handled_however_late`);
  a request the layer stopped reporting would keep its entry.
- libp2p-swarm 0.48.0 `handler.rs:542`: `SubstreamProtocol::new` times a stream upgrade out after
  10 s. With our 15 s request timeout that bounds every block request at about 25 s, the reason
  the in-flight sweep (`BLOCK_REQ_TIMEOUT_SECS`, 60 s) only frees slots and blames nobody.
- libp2p-swarm 0.48.0 `lib.rs:1553`, libp2p-tcp 0.45.0 `lib.rs:396-416` and
  `provider/tokio.rs:94-98`, libp2p-core 0.44.0 `transport/boxed.rs:173-175`: a failed dial
  reports each address with its own error, the TCP transport has no connect timeout of its own,
  and the kernel's error is wrapped by `io::Error::other`; `timed_out_dial_addrs` finds a timeout
  by the text `TimedOut` in that error ("Address book"). The transport's handshake deadline
  (`Multiplexed::timeout`, libp2p-core 0.44.0 `upgrade.rs:313`, wrapping the dial and the listener
  upgrade, `transport/timeout.rs:92-93`) ends a dial first, as `TransportTimeoutError::Timeout`
  (`transport/timeout.rs:180-188`), whose Debug text inside the boxed `io::Error` is
  `error: Timeout }`; `dial_error_text_is_timeout` matches it
  (`a_dial_past_our_handshake_deadline_reads_as_a_timeout` builds it from the crate's types).
- libp2p-connection-limits 0.7.0 `lib.rs:235-386`, the model of our own `ConnectionCaps`
  (`src/net/admission.rs`; the crate is compiled as a libp2p dependency but not used): the
  pending-inbound limit is checked before the handshake, and the per-peer and inbound limits after it
  (`handle_established_inbound_connection`, `handle_established_outbound_connection`), so a refused
  third connection of a peer is one the remote saw open and close, not a failed dial; the counts
  move on `ConnectionEstablished`, `ConnectionClosed` and `ListenFailure` (`:344-386`; the crate
  also counts pending dials on `DialFailure`, a limit we do not set). The crate never removes a
  peer's empty set (`:353-356`, made at `:373-376`), so it keeps an entry for every identity that
  ever connected; `ConnectionCaps` drops it with the peer's last connection
  (`tests/admission_identity_churn.rs`). libp2p-swarm 0.48.0 `behaviour.rs:137-209` and
  `lib.rs:955-971`, `:743-748`, `:859`: every composed behaviour's
  `handle_pending_inbound_connection` runs until one refuses, and the swarm then reports
  `ListenFailure` to all of them, which is where `InboundPerAddress` frees a refused or failed
  handshake's slot.
- libp2p-gossipsub 0.50.1, with `validate_messages` (`config.rs:822-823`): a received message is
  put in the cache unvalidated and not forwarded (`behaviour.rs:2022`, `:2046-2052`); Accept
  forwards it and Ignore removes it (`report_message_validation_result`, `:949-1008`); only
  validated messages are announced or served (`mcache.rs:122-130`, `:162-173`), and an unreported
  one leaves the cache at the shift after `history_length` heartbeats (`:192-210`; 5,
  `config.rs:515`). `publish` refuses an id the duplicate cache holds (`behaviour.rs:658-666`;
  `config.rs:524`, 60 s) and inserts the id before it can fail with `AllQueuesFull` (`:701-702`,
  `:737`), the order PublishRetry relies on; a publish with no subscribed peer fails before the
  insert (`:694-697`). The cache prunes lazily: `contains` ignores expiry (`time_cache.rs:164-166`,
  `:192-194`) and an expired id goes only when another is recorded (`TimeCache::entry`, `:138-140`,
  through `:701` and `:1992`), as in 0.48 (`behaviour.rs:621`, `:739`, `:1793`). So PublishRetry
  keeps an entry while it matters (a tx whose bytes the mempool holds, a mined header at our tip),
  not for a number of attempts (`publish_retry_tests`). Under `ValidationMode::Permissive` a
  signature is checked only when present (`protocol.rs:409-419`) and `from` is decoded without
  binding (`:527-555`), and the app-facing `Message` has no signature field (`types.rs:209-220`):
  why the node never trusts `message.source`. Our publishes share one data queue with forwards,
  IHAVE and IWANT (`queue.rs:36-84`, `connection_handler_queue_len` 5000), so `AllQueuesFull` on our
  own mined header is likelier under relay load than on 0.48; PublishRetry covers it. A peer that
  stops reading costs that queue and one stream window, then `publish` reports `AllQueuesFull`
  (`behaviour.rs:736-737`; `gossip_wire_tests::a_peer_that_stops_reading_fills_a_bounded_queue`).
- libp2p-gossipsub 0.50.1 control size: an RPC whose control part exceeds
  `max_control_message_size` (default 16 KiB, `config.rs:557`) is refused and its stream closed
  (`protocol.rs:332-341`, `handler.rs:362-368`), and the fifth stream on a connection disables
  gossipsub there (`handler.rs:82, 483-503`). `emit_gossip` truncates an IHAVE only at
  `max_control_messages_sent` (`behaviour.rs:2849-2855`), and at 66 bytes per id (64-hex ids) a
  catch-up burst of headers overflows 16 KiB. So `MAX_GOSSIP_IDS_PER_CONTROL` (200) caps what we
  send, and `MAX_GOSSIP_CONTROL_BYTES_RECEIVED` (`MAX_GOSSIP_MSG_BYTES`, 256 KiB) keeps the receive
  bound of gossipsub 0.48 and earlier, because upstream v1.1.2's 0.47.0 (its `Cargo.lock`; 0.47.0
  `config.rs:416`, `behaviour.rs:2452-2457`) sends IHAVEs of up to 5000 ids with no control limit.
  The receive bound can return to the 16 KiB default once no peer on the network sends a control
  part above 16 KiB, measured on the network. Pinned in both directions by
  `gossip_wire_tests::a_catch_up_burst_keeps_gossip_flowing_to_a_peer_outside_the_mesh`.
- libp2p-identity 0.3.0 `keypair.rs:215, 257`: `to_protobuf_encoding` and
  `from_protobuf_encoding`, which read and write `nodekey.ed25519`. A key written by 0.2.13
  (upstream's version) decodes to the same PeerId and re-encodes byte for byte (`node_key_tests`); a
  change there would change every node's PeerId on upgrade.
- bincode 1.3.3 `config/mod.rs:84-102`: `DefaultOptions` refuses trailing bytes, which
  `decode_wire` (`src/net/node.rs`) keeps by not calling `allow_trailing_bytes`.
