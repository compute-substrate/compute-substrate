// csd-sites: a door's site store. It keeps the sites that .csd names point to and serves them, so a
// site stays up when its author's own computer is off, or can't be reached, as most home and mobile
// connections can't.
//
//   GET  /sites/<cid>.car   the site, as a .car file (HEAD: whether this door has it)
//   POST /sites/<cid>.car   give this door a site. Kept only if a name's profile points to it, and
//                           only once every block checks out against <cid>.
//   GET  /sites             what this door keeps
//
// Readers check every block against the address the name points to, as they would from anyone,
// so a door is trusted with nothing. Anyone can run one; the Compute Substrate Node app gives the
// sites it has to the doors it knows, and reads from them.
//
// It reads names from its own node (its RPC, --node), and runs beside it, usually behind the same
// web server (Caddy) as the node's public RPC. Nothing here is consensus.

mod car;
mod index;

use clap::Parser;
use index::Index;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const MAX_SITE: usize = 64 * 1024 * 1024;

#[derive(Parser)]
#[command(about = "A door's site store: keeps the sites .csd names point to, and serves them")]
struct Args {
    /// this machine's node, its RPC
    #[arg(long, default_value = "http://127.0.0.1:8789")]
    node: String,
    /// where the sites are kept
    #[arg(long, default_value = "/var/lib/csd/sites")]
    dir: PathBuf,
    /// where it answers; usually only this machine, with a web server in front
    #[arg(long, default_value = "127.0.0.1:8795")]
    listen: String,
    /// the most it keeps, in GB; past that it takes no new sites
    #[arg(long, default_value_t = 20)]
    max_gb: u64,
    /// answer browsers from any site itself (when no web server in front adds these headers)
    #[arg(long)]
    cors: bool,
    /// sites this door won't keep or serve: a file of CIDs and .csd names, one per line (`#` starts a
    /// note). Read again every minute; what it lists is dropped at once.
    #[arg(long)]
    deny: Option<PathBuf>,
    /// this door's own address, so it doesn't copy from itself
    #[arg(long)]
    url: Option<String>,
    /// another door to copy sites from, besides those announced on the network (repeatable)
    #[arg(long = "door")]
    doors: Vec<String>,
}

struct Door {
    dir: PathBuf,
    index: Mutex<Index>,
    max_bytes: u64,
    cors: bool,
    deny_file: Option<PathBuf>,
    deny: Mutex<Deny>,
}

// What the operator won't keep: sites by CID, and every site a denied name points to
#[derive(Default)]
struct Deny {
    cids: std::collections::HashSet<String>,
    names: std::collections::HashSet<String>,
}

impl Deny {
    fn read(file: &Path) -> Deny {
        let mut d = Deny::default();
        for line in fs::read_to_string(file).unwrap_or_default().lines() {
            let l = line.split('#').next().unwrap_or("").trim().to_ascii_lowercase();
            let l = l.trim_start_matches("ipfs://");
            if l.is_empty() {
                continue;
            }
            if car::parse_cid(l).is_some() {
                d.cids.insert(l.to_string());
            } else {
                d.names.insert(l.trim_end_matches(".csd").to_string());
            }
        }
        d
    }
}

impl Door {
    fn denied(&self, cid: &str) -> bool {
        let d = self.deny.lock().unwrap();
        d.cids.contains(cid) || (!d.names.is_empty() && self.index.lock().unwrap().current.iter()
            .any(|(k, (c, _))| c == cid && d.names.contains(k.split(' ').next().unwrap_or(""))))
    }
}

fn car_path(dir: &Path, cid: &str) -> PathBuf {
    dir.join(format!("{cid}.car"))
}

fn kept(dir: &Path) -> Vec<(String, u64)> {
    let Ok(rd) = fs::read_dir(dir) else { return vec![] };
    rd.flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            let cid = n.strip_suffix(".car")?.to_string();
            car::parse_cid(&cid)?;
            Some((cid, e.metadata().ok()?.len()))
        })
        .collect()
}

fn save_index(dir: &Path, index: &Index) {
    let tmp = dir.join("index.json.tmp");
    if fs::write(&tmp, serde_json::to_vec(index).unwrap()).is_ok() {
        let _ = fs::rename(tmp, dir.join("index.json"));
    }
}

// Every minute: read the node's new records, and drop sites no name has wanted for the grace period
// The other doors: those given with --door, and every door announced on the network (a record under
// csd.doors whose text is its address), read from this door's own node
fn other_doors(node: &str, given: &[String], me: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = given.iter().map(|d| d.trim_end_matches('/').to_string()).collect();
    if let Ok(r) = ureq::get(&format!("{node}/proposals/csd.doors/200")).timeout(Duration::from_secs(30)).call() {
        if let Ok(j) = r.into_json::<serde_json::Value>() {
            for p in j["proposals"].as_array().cloned().unwrap_or_default() {
                let u = p["uri"].as_str().unwrap_or("").trim().trim_end_matches('/').to_string();
                let host = u.strip_prefix("https://").unwrap_or("");
                if !host.is_empty() && host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':') && !out.contains(&u) {
                    out.push(u);
                }
            }
        }
    }
    let me = me.map(|m| m.trim_end_matches('/'));
    out.retain(|d| Some(d.as_str()) != me);
    out.truncate(40);
    out
}

// Copy, from the other doors, every site a name points to that this door doesn't have yet: so a new
// door has every named site within minutes, and a site survives any one door going away. Each one is
// checked like any site given to this door.
fn fill(door: &Door, node: &str, given: &[String], me: Option<&str>) {
    let ix = door.index.lock().unwrap();
    let mut want: Vec<String> = ix.current.values().map(|(c, _)| c.clone()).collect();
    drop(ix);
    want.sort();
    want.dedup();
    let held: std::collections::HashSet<String> = kept(&door.dir).into_iter().map(|(c, _)| c).collect();
    want.retain(|c| !held.contains(c) && !door.denied(c));
    if want.is_empty() {
        return;
    }
    let doors = other_doors(node, given, me);
    for cid in want {
        let root = car::parse_cid(&cid).unwrap();
        for d in &doors {
            let Ok(r) = ureq::get(&format!("{d}/sites/{cid}.car")).timeout(Duration::from_secs(180)).call() else { continue };
            let mut body = Vec::new();
            if r.into_reader().take(MAX_SITE as u64 + 1).read_to_end(&mut body).is_err() || body.len() > MAX_SITE {
                continue;
            }
            let used: u64 = kept(&door.dir).iter().map(|(_, n)| n).sum();
            if used + body.len() as u64 > door.max_bytes {
                eprintln!("[sites] full: not copying {cid}");
                return;
            }
            if let Err(e) = car::check(&body, root) {
                eprintln!("[sites] {d} sent {cid} broken ({e}); trying another door");
                continue;
            }
            let (tmp, file) = (door.dir.join(format!("{cid}.car.part")), car_path(&door.dir, &cid));
            if fs::write(&tmp, &body).and_then(|_| fs::rename(&tmp, &file)).is_ok() {
                eprintln!("[sites] copied {cid} from {d}");
            }
            break;
        }
    }
}

fn follow(node: String, door: Arc<Door>, given: Vec<String>, me: Option<String>) {
    let mut filled_at: Option<std::time::Instant> = None;
    loop {
        let mut ix = std::mem::take(&mut *door.index.lock().unwrap());
        match index::catch_up(&node, &mut ix) {
            Ok(()) => {}
            Err(e) => eprintln!("[sites] {e}"),
        }
        // forget long-dropped sites
        let tip = ix.tip;
        ix.dropped.retain(|_, h| *h + index::GRACE_BLOCKS > tip);
        save_index(&door.dir, &ix);
        *door.index.lock().unwrap() = ix;
        if let Some(f) = &door.deny_file {
            *door.deny.lock().unwrap() = Deny::read(f);
        }
        for (cid, _) in kept(&door.dir) {
            let why = if door.denied(&cid) { Some("on the deny list") } else if !door.index.lock().unwrap().wanted(&cid) { Some("no name points to it any more") } else { None };
            if let Some(why) = why {
                eprintln!("[sites] dropping {cid}: {why}");
                let _ = fs::remove_file(car_path(&door.dir, &cid));
            }
        }
        // every 10 minutes, once the names are read
        let caught_up = { let ix = door.index.lock().unwrap(); ix.tip > 0 && ix.next > ix.tip };
        if caught_up && filled_at.is_none_or(|t| t.elapsed() >= Duration::from_secs(600)) {
            filled_at = Some(std::time::Instant::now());
            fill(&door, &node, &given, me.as_deref());
        }
        std::thread::sleep(Duration::from_secs(60));
    }
}

fn respond(req: tiny_http::Request, door: &Door, status: u16, body: Vec<u8>, kind: &str) {
    let mut r = tiny_http::Response::from_data(body).with_status_code(status)
        .with_header(tiny_http::Header::from_bytes("Content-Type", kind).unwrap());
    if door.cors {
        for (k, v) in [("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Methods", "GET, HEAD, POST, OPTIONS"), ("Access-Control-Allow-Headers", "content-type"), ("Access-Control-Max-Age", "600")] {
            r.add_header(tiny_http::Header::from_bytes(k, v).unwrap());
        }
    }
    let _ = req.respond(r);
}

fn text(req: tiny_http::Request, door: &Door, status: u16, msg: &str) {
    respond(req, door, status, serde_json::to_vec(&serde_json::json!({ "ok": status < 300, "message": msg })).unwrap(), "application/json");
}

fn handle(mut req: tiny_http::Request, door: &Door) {
    use tiny_http::Method::*;
    let path = req.url().split('?').next().unwrap_or("").to_string();
    if *req.method() == Options {
        return respond(req, door, 204, vec![], "text/plain");
    }
    if path == "/sites" || path == "/sites/" {
        let ks = kept(&door.dir);
        let ix = door.index.lock().unwrap();
        let body = serde_json::json!({
            "ok": true,
            "sites": ks.iter().map(|(c, n)| serde_json::json!({ "cid": c, "bytes": n })).collect::<Vec<_>>(),
            "names_read_to": ix.next.saturating_sub(1),
            "tip": ix.tip,
        });
        drop(ix);
        return respond(req, door, 200, serde_json::to_vec(&body).unwrap(), "application/json");
    }
    let Some(cid) = path.strip_prefix("/sites/").and_then(|p| p.strip_suffix(".car")).filter(|c| car::parse_cid(c).is_some()).map(str::to_string) else {
        return text(req, door, 404, "Not here. This door serves /sites/<cid>.car.");
    };
    let file = car_path(&door.dir, &cid);
    if door.denied(&cid) {
        let _ = fs::remove_file(&file);
        return text(req, door, 451, "This door doesn't keep or serve that site.");
    }
    match req.method() {
        Get | Head => match fs::read(&file) {
            // ?path=index.html: just that file, with the folders on the way to it (at most 1 MB)
            Ok(b) if req.url().contains("?path=") => {
                let want = req.url().split("?path=").nth(1).unwrap_or("").split('&').next().unwrap_or("");
                let want = percent_decode(want);
                match car::path_car(&b, car::parse_cid(&cid).unwrap(), &want, 1 << 20) {
                    Ok(Some(part)) => respond(req, door, 200, part, "application/vnd.ipld.car"),
                    _ => text(req, door, 404, "That site has no such file, or it's over 1 MB."),
                }
            }
            Ok(b) => {
                let head = *req.method() == Head;
                respond(req, door, 200, if head { vec![] } else { b }, "application/vnd.ipld.car")
            }
            Err(_) => text(req, door, 404, "This door doesn't have that site."),
        },
        Post => {
            if file.exists() {
                return text(req, door, 200, "This door has it already.");
            }
            if !door.index.lock().unwrap().wanted(&cid) {
                return text(req, door, 403, "No .csd name points to this site, so this door doesn't keep it. Point a name to it first (its site, ipfs://<cid>), and give it again once that record is in a block.");
            }
            let mut body = Vec::new();
            if req.as_reader().take(MAX_SITE as u64 + 1).read_to_end(&mut body).is_err() {
                return text(req, door, 400, "The upload broke off.");
            }
            if body.len() > MAX_SITE {
                return text(req, door, 413, "A site can be at most 64 MB.");
            }
            let used: u64 = kept(&door.dir).iter().map(|(_, n)| n).sum();
            if used + body.len() as u64 > door.max_bytes {
                return text(req, door, 507, "This door is full.");
            }
            if let Err(e) = car::check(&body, car::parse_cid(&cid).unwrap()) {
                return text(req, door, 422, &format!("That isn't this site intact: {e}."));
            }
            let tmp = door.dir.join(format!("{cid}.car.part"));
            if fs::write(&tmp, &body).and_then(|_| fs::rename(&tmp, &file)).is_err() {
                return text(req, door, 500, "Couldn't save it.");
            }
            eprintln!("[sites] keeping {cid} ({} bytes)", body.len());
            text(req, door, 201, "Kept. This door serves it from now on.")
        }
        _ => text(req, door, 405, "GET, HEAD or POST."),
    }
}

fn main() {
    let a = Args::parse();
    fs::create_dir_all(&a.dir).unwrap_or_else(|e| panic!("can't use {}: {e}", a.dir.display()));
    let index: Index = fs::read(a.dir.join("index.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    let deny = a.deny.as_deref().map(Deny::read).unwrap_or_default();
    let door = Arc::new(Door { dir: a.dir.clone(), index: Mutex::new(index), max_bytes: a.max_gb * 1_000_000_000, cors: a.cors, deny_file: a.deny.clone(), deny: Mutex::new(deny) });
    let node = a.node.trim_end_matches('/').to_string();
    {
        let door = door.clone();
        let (given, me) = (a.doors.clone(), a.url.clone());
        std::thread::spawn(move || follow(node, door, given, me));
    }
    let server = Arc::new(tiny_http::Server::http(&a.listen).unwrap_or_else(|e| panic!("can't listen on {}: {e}", a.listen)));
    eprintln!("[sites] keeping sites in {}, answering on {}", a.dir.display(), a.listen);
    let workers: Vec<_> = (0..8).map(|_| {
        let (server, door) = (server.clone(), door.clone());
        std::thread::spawn(move || {
            for req in server.incoming_requests() {
                handle(req, &door);
            }
        })
    }).collect();
    for w in workers {
        let _ = w.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_decide_what_is_kept() {
        let mut ix = Index { tip: 100_000, ..Default::default() };
        let (a, b) = ("bafybeih4sszbxx3lao542tqhzwa37uk2clof5vxddvtbpqqp5nyaidsh24".to_string(), "bafybeicnb2kolu7wllsf7mn4lmkbz36jwww7gtave57s7cwzwsdz6l2y7q".to_string());
        ix.apply("commonplace", "owner", Some(a.clone()), 90_000);
        assert!(ix.wanted(&a) && !ix.wanted(&b));
        // someone else's profile for the same name doesn't push the owner's site out
        ix.apply("commonplace", "stranger", Some(b.clone()), 90_001);
        assert!(ix.wanted(&a) && ix.wanted(&b));
        // the owner moves on: the old site stays for the grace period, then goes
        ix.apply("commonplace", "owner", Some(b.clone()), 95_000);
        assert!(ix.wanted(&a));
        ix.tip = 95_000 + index::GRACE_BLOCKS;
        assert!(!ix.wanted(&a) && ix.wanted(&b));
        // an older record read again changes nothing
        ix.apply("commonplace", "owner", Some(a.clone()), 90_000);
        assert!(!ix.wanted(&a));
        assert_eq!(index::profile_site(r#"{"v":1,"t":"nprofile","name":"x","p":{"contenthash":"ipfs://bafybeih4sszbxx3lao542tqhzwa37uk2clof5vxddvtbpqqp5nyaidsh24"}}"#), Some(("x".into(), Some(a.clone()))));
        assert_eq!(index::profile_site(r#"{"v":1,"t":"nprofile","name":"x","p":{"url":"https://x"}}"#), Some(("x".into(), None)));
        assert_eq!(index::profile_site(r#"{"v":1,"t":"nreg","name":"x"}"#), None);
    }

    #[test]
    fn the_deny_list_takes_sites_and_names() {
        let f = std::env::temp_dir().join(format!("csd-deny-{}", std::process::id()));
        fs::write(&f, "# not here\nbafybeih4sszbxx3lao542tqhzwa37uk2clof5vxddvtbpqqp5nyaidsh24\nbadname.csd  # a note\n\n").unwrap();
        let mut ix = Index { tip: 100_000, ..Default::default() };
        ix.apply("badname", "someone", Some("bafybeicnb2kolu7wllsf7mn4lmkbz36jwww7gtave57s7cwzwsdz6l2y7q".into()), 90_000);
        let door = Door { dir: std::env::temp_dir(), index: Mutex::new(ix), max_bytes: 0, cors: false, deny_file: None, deny: Mutex::new(Deny::read(&f)) };
        assert!(door.denied("bafybeih4sszbxx3lao542tqhzwa37uk2clof5vxddvtbpqqp5nyaidsh24"));
        assert!(door.denied("bafybeicnb2kolu7wllsf7mn4lmkbz36jwww7gtave57s7cwzwsdz6l2y7q")); // badname points to it
        assert!(!door.denied("bafybeifud7i3hbqspxqonhaj3kf7ertxinqbeukiu6icgizjvbmbw624oi"));
        fs::remove_file(&f).ok();
    }

    #[test]
    fn checks_a_real_site() {
        let Ok(car) = std::env::var("TEST_CAR") else { return };
        let bytes = fs::read(&car).unwrap();
        let root = car::parse_cid(&std::env::var("TEST_CID").unwrap()).unwrap();
        assert!(car::check(&bytes, root).unwrap() > 1000);
        // one byte changed anywhere in the blocks: refused
        let mut bad = bytes.clone();
        let i = bad.len() / 2;
        bad[i] ^= 1;
        assert!(car::check(&bad, root).is_err());
        // a block missing: refused
        assert!(car::check(&bytes[..bytes.len() - 5000], root).is_err());
        // a different site's address: refused
        let other = car::parse_cid("bafybeicnb2kolu7wllsf7mn4lmkbz36jwww7gtave57s7cwzwsdz6l2y7q").unwrap();
        assert!(car::check(&bytes, other).is_err());
        // one file of it, as a .car of its own: much smaller, and only for files that are there
        let part = car::path_car(&bytes, root, "index.html", 1 << 20).unwrap().unwrap();
        assert!(part.len() < bytes.len() / 4);
        assert!(car::path_car(&bytes, root, "nothing-here.html", 1 << 20).unwrap().is_none());
        assert!(car::path_car(&bytes, root, "_next", 1 << 20).unwrap().is_none());
        assert!(car::path_car(&bytes, root, "index.html", 10).unwrap().is_none());
        if let Ok(out) = std::env::var("TEST_OUT") {
            fs::write(out, &part).unwrap();
        }
    }

    #[test]
    fn decodes_paths() {
        assert_eq!(percent_decode("icon%2Fa%20b.png"), "icon/a b.png");
        assert_eq!(percent_decode("a%2"), "a%2");
    }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
