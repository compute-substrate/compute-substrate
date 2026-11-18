// Compute Substrate Node, the app: runs the `csd` node that ships inside it, on this computer, with no
// terminal. It keeps the node's data in the app's own folder, starts it when the app opens and stops
// it cleanly when the app closes. The window shows how far the node has synced; apps on this
// computer (and web pages in its browser) can use the node at http://127.0.0.1:8789.
//
// The node is the same program an operator builds from this repository. The app only starts it,
// with these arguments, and watches it.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::Serialize;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{Emitter, Manager, RunEvent, WindowEvent};

const RPC: &str = "127.0.0.1:8789";
const P2P: &str = "/ip4/0.0.0.0/tcp/17999";
const BOOTNODES: &str = include_str!("../../bootnodes.txt");
// How long a clean stop may take before the node is killed. The node flushes its database on the
// way out. A stop during its startup rebuild (below) doesn't wait: the node would finish the
// rebuild before stopping, and every start rebuilds from scratch anyway, so nothing is lost.
const STOP_WAIT: Duration = Duration::from_secs(120);

#[derive(Clone, Serialize, Default)]
struct State {
    /// starting | running | elsewhere | stopping | stopped | failed
    phase: String,
    message: String,
    /// how far a rebuild has got, 0..1, when the node says how many blocks it replays
    progress: Option<f64>,
    rpc: String,
    datadir: String,
}

#[derive(Default)]
struct Node {
    child: Mutex<Option<Child>>,
    state: Mutex<State>,
    stopping: Mutex<bool>,
    log: Mutex<LogWatch>,
}

// What the node is doing while it starts, read from its log as the log grows. Each time it starts,
// the node rebuilds its copy of the network's state from the blocks it already has, before it
// answers anyone, so nothing half-written can carry over: one `[tip] set_tip` line per block, after
// a `[reorg] recovery fallback` line (and, from newer nodes, a line with the number of blocks).
#[derive(Default)]
struct LogWatch {
    path: PathBuf,
    pos: u64,
    rebuilding: bool,
    replayed: u64,
    total: Option<u64>,
}

impl LogWatch {
    fn new(path: PathBuf) -> Self {
        LogWatch { path, ..Default::default() }
    }

    fn update(&mut self) {
        let Ok(mut f) = File::open(&self.path) else { return };
        if f.seek(SeekFrom::Start(self.pos)).is_err() {
            return;
        }
        let mut buf = Vec::new();
        if f.take(16 << 20).read_to_end(&mut buf).is_err() {
            return;
        }
        // only whole lines; the rest is read next time
        let Some(end) = buf.iter().rposition(|&b| b == b'\n') else { return };
        self.pos += end as u64 + 1;
        for line in String::from_utf8_lossy(&buf[..end]).lines() {
            if line.starts_with("[reorg] recovery fallback: rebuilding") {
                self.rebuilding = true;
                self.replayed = 0;
                self.total = None;
            } else if let Some(n) = line.strip_prefix("[reorg] rebuild: replaying ") {
                self.total = n.split(' ').next().and_then(|n| n.parse().ok());
            } else if self.rebuilding && line.starts_with("[tip] set_tip:") {
                self.replayed += 1;
            }
        }
    }

    fn rebuilding(&self) -> bool {
        self.rebuilding && self.total.map_or(true, |t| self.replayed < t)
    }

    fn fraction(&self) -> Option<f64> {
        self.total.filter(|&t| t > 0).map(|t| self.replayed as f64 / t as f64)
    }

    fn progress(&self) -> String {
        match self.total {
            Some(t) if t > 0 => format!("Block {} of {} ({}%).", group(self.replayed), group(t), self.replayed * 100 / t),
            _ => format!("{} blocks so far.", group(self.replayed)),
        }
    }
}

fn group(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

impl Node {
    fn set(&self, phase: &str, message: impl Into<String>) {
        let mut s = self.state.lock().unwrap();
        s.phase = phase.into();
        s.message = message.into();
        s.progress = None;
    }
    fn set_rebuild(&self, phase: &str, message: String, w: &LogWatch) {
        self.set(phase, message);
        self.state.lock().unwrap().progress = w.fraction();
    }
}

// The peers a node starts from: the list shipped with the app (bootnodes.txt), and any added in the
// window (added-peers.txt in the data folder). The node is given them all as bootnodes, so it dials
// them at start and again whenever it's short of peers, and never drops them from its book. Once
// connected it learns more and keeps those in its own peers.txt, so these matter mostly for a first
// start, or a start long after the shipped list has gone stale.
const ADDED_PEERS: &str = "added-peers.txt";

fn peer_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#'))
}

fn bootnodes(dir: &Path) -> String {
    let added = fs::read_to_string(dir.join(ADDED_PEERS)).unwrap_or_default();
    let mut seen = std::collections::HashSet::new();
    peer_lines(BOOTNODES)
        .chain(peer_lines(&added))
        .filter(|l| valid_peer(l))
        .filter(|l| seen.insert(l.to_string()))
        .collect::<Vec<_>>()
        .join(",")
}

// A peer's full address as the node takes it: /ip4, /ip6 or /dns… with a TCP port, ending in its
// /p2p/ id. Only the characters an address has, so nothing else reaches the node's arguments.
fn valid_peer(a: &str) -> bool {
    let parts: Vec<&str> = a.split('/').collect();
    parts.len() == 7
        && parts[0].is_empty()
        && matches!(parts[1], "ip4" | "ip6" | "dns" | "dns4" | "dns6")
        && !parts[2].is_empty()
        && parts[2].chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-'))
        && parts[3] == "tcp"
        && parts[4].parse::<u16>().map_or(false, |p| p > 0)
        && parts[5] == "p2p"
        && parts[6].len() >= 46
        && parts[6].len() <= 64
        && parts[6].chars().all(|c| c.is_ascii_alphanumeric())
}

// The node program, next to the app's own executable (that's where the installer puts it)
fn node_binary() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = exe.parent().ok_or("no folder for the app")?;
    let name = if cfg!(windows) { "csd.exe" } else { "csd" };
    let p = dir.join(name);
    if p.exists() { Ok(p) } else { Err(format!("The node program is missing from the app ({}).", p.display())) }
}

#[allow(unused_mut)]
fn command(bin: &Path) -> Command {
    let mut c = Command::new(bin);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        c.creation_flags(CREATE_NO_WINDOW);
    }
    c
}

// The last lines the node wrote, for a message when it stops on its own
fn tail(log: &Path, n: usize) -> String {
    let Ok(f) = File::open(log) else { return String::new() };
    let lines: Vec<String> = BufReader::new(f).lines().map_while(Result::ok).collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

fn port_in_use(addr: &str) -> bool {
    TcpListener::bind(addr).is_err()
}

fn answers(addr: &str) -> bool {
    let a: SocketAddr = addr.parse().unwrap();
    TcpStream::connect_timeout(&a, Duration::from_secs(2)).is_ok()
}

fn start(app: &tauri::AppHandle, node: &Arc<Node>) -> Result<(), String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?.join("node");
    fs::create_dir_all(&dir).map_err(|e| format!("Can't create the data folder {}: {e}", dir.display()))?;
    {
        let mut s = node.state.lock().unwrap();
        s.rpc = format!("http://{RPC}");
        s.datadir = dir.display().to_string();
    }

    // Another node already on this computer (an operator's, or a second copy of the app): use it
    // rather than fight it for the port.
    if port_in_use(RPC) {
        if answers(RPC) {
            node.set("elsewhere", "Another node is already running on this computer. Showing that one.");
            return Ok(());
        }
        return Err(format!("Something else is using {RPC}, the address the node needs."));
    }

    let bin = node_binary()?;

    // Genesis, made here by the node itself: it's deterministic, so there's no file to download or trust
    let genesis = dir.join("genesis.bin");
    if !genesis.exists() {
        let out = command(&bin)
            .arg("genesis")
            .arg("--out")
            .arg(&genesis)
            .output()
            .map_err(|e| format!("Can't run the node program: {e}"))?;
        if !out.status.success() {
            return Err(format!("Making the genesis block failed: {}", String::from_utf8_lossy(&out.stderr)));
        }
    }

    // Its log, one file per run (the previous run's is kept beside it)
    let log = dir.join("node.log");
    if log.exists() {
        let _ = fs::rename(&log, dir.join("node.previous.log"));
    }
    let out = File::create(&log).map_err(|e| e.to_string())?;
    let err = out.try_clone().map_err(|e| e.to_string())?;

    let mut c = command(&bin);
    c.arg("node")
        .arg("--datadir").arg(dir.join("db"))
        .arg("--rpc").arg(RPC)
        .arg("--genesis").arg(&genesis)
        .arg("--p2p-listen").arg(P2P)
        .arg("--rpc-allow-any-origin")
        .arg("--stop-on-stdin-close");
    let boot = bootnodes(&dir);
    if !boot.is_empty() {
        c.arg("--bootnodes").arg(boot);
    }
    // stdin stays open for as long as the app wants the node running; closing it stops the node
    let child = c
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .map_err(|e| format!("Can't start the node: {e}"))?;
    *node.child.lock().unwrap() = Some(child);
    *node.log.lock().unwrap() = LogWatch::new(log.clone());
    node.set("starting", "");

    // Watch it: running once its RPC answers; a message if it stops without being asked to
    let n = node.clone();
    let handle = app.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(500));
        let mut guard = n.child.lock().unwrap();
        let Some(child) = guard.as_mut() else { return };
        match child.try_wait() {
            Ok(Some(status)) => {
                *guard = None;
                drop(guard);
                if !*n.stopping.lock().unwrap() {
                    n.set("failed", format!("The node stopped ({status}).\n\n{}", tail(&log, 12)));
                    let _ = handle.emit("node-changed", ());
                }
                return;
            }
            Ok(None) => {
                drop(guard);
                let phase = n.state.lock().unwrap().phase.clone();
                if phase == "starting" {
                    if answers(RPC) {
                        n.set("running", "");
                        let _ = handle.emit("node-changed", ());
                    } else {
                        let mut w = n.log.lock().unwrap();
                        w.update();
                        if w.rebuilding() {
                            n.set_rebuild("starting", format!(
                                "Each time it starts, your node rebuilds its copy of the network from the blocks it already has, so nothing half-written carries over. Leave the app open until it's done.\n\n{}",
                                w.progress()
                            ), &w);
                            let _ = handle.emit("node-changed", ());
                        }
                    }
                }
            }
            Err(_) => return,
        }
    });
    Ok(())
}

// A clean stop: close the node's stdin and wait for it to flush and exit; kill it only if it hangs
fn stop(node: &Node) {
    *node.stopping.lock().unwrap() = true;
    let child = node.child.lock().unwrap().take();
    let Some(mut child) = child else { return };
    node.set("stopping", "Stopping the node…");
    drop(child.stdin.take());
    let t = Instant::now();
    loop {
        if let Ok(Some(_)) = child.try_wait() {
            node.set("stopped", "");
            return;
        }
        let mut w = node.log.lock().unwrap();
        w.update();
        if w.rebuilding() || t.elapsed() >= STOP_WAIT {
            break;
        }
        drop(w);
        std::thread::sleep(Duration::from_millis(200));
    }
    let _ = child.kill();
    let _ = child.wait();
    node.set("stopped", "");
}

// ── Commonplace, from this computer ─────────────────────────────────────────
// The app carries a release of Commonplace (app/commonplace.json pins which, by its IPFS address)
// and serves it here, on this computer only, so it opens with no website in between. It's one
// example of an app on the network; it reads through this computer's own node.
pub const LOCAL_SITE: &str = "127.0.0.1:8790";

fn mime(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "wasm" => "application/wasm",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

// Serves a folder at `addr`, on this computer only. `root` can change while it runs (a name that
// points to a newer site keeps its address). Only files inside the folder, nothing else.
fn serve_dir(server: tiny_http::Server, root: Arc<Mutex<PathBuf>>) {
    for req in server.incoming_requests() {
        let path = req.url().split(['?', '#']).next().unwrap_or("/").to_string();
        let Ok(root) = root.lock().unwrap().canonicalize() else {
            let _ = req.respond(tiny_http::Response::from_data(b"not found".to_vec()).with_status_code(404));
            continue;
        };
        let rel = path.trim_start_matches('/');
        let rel = percent_decode(rel);
        let mut file = root.join(if rel.is_empty() { "index.html".to_string() } else { rel.clone() });
        if file.is_dir() {
            file = file.join("index.html");
        } else if !file.exists() && !rel.is_empty() && !rel.rsplit('/').next().unwrap_or("").contains('.') {
            // /about served from about.html, as static sites are usually built
            file = root.join(format!("{rel}.html"));
        }
        let inside = |f: &Path| f.canonicalize().map(|f| f.starts_with(&root) && f.is_file()).unwrap_or(false);
        let (file, status) = if inside(&file) {
            (Some(file), 200)
        } else if inside(&root.join("404.html")) {
            (Some(root.join("404.html")), 404)
        } else {
            (None, 404)
        };
        let resp = match file.and_then(|f| fs::read(&f).ok().map(|b| (f, b))) {
            Some((f, bytes)) => tiny_http::Response::from_data(bytes)
                .with_header(tiny_http::Header::from_bytes(&b"Content-Type"[..], mime(&f.to_string_lossy()).as_bytes()).unwrap())
                .with_header(tiny_http::Header::from_bytes(&b"Cache-Control"[..], &b"no-cache"[..]).unwrap())
                .with_status_code(status),
            None => tiny_http::Response::from_data(b"not found".to_vec()).with_status_code(404),
        };
        let _ = req.respond(resp);
    }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() && s.is_char_boundary(i + 1) && s.is_char_boundary(i + 3) {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn serve_site(root: PathBuf) {
    match tiny_http::Server::http(LOCAL_SITE) {
        Ok(server) => serve_dir(server, Arc::new(Mutex::new(root))),
        Err(e) => eprintln!("[site] can't serve Commonplace on {LOCAL_SITE}: {e}"),
    }
}

// ── Sites of .csd names ─────────────────────────────────────────────────────
// A name whose profile points to a site (contenthash ipfs://<CIDv1>) opens from this computer too.
// The window downloads the site from IPFS and checks every block against the address the name
// points to (resolver/src/site.ts); the app keeps the checked files (sites/<cid>/) and serves each
// name on a port of its own, from http://localhost:8801 up. A port per name keeps sites apart: each
// is its own origin, with its own storage and logins, and keeps it when the name points to a
// newer site. Your normal browser opens it, so wallets and everything else work as on any website.
const FIRST_SITE_PORT: u16 = 8801;

#[derive(Default)]
struct Sites {
    // name -> (port, folder being served)
    served: Mutex<std::collections::HashMap<String, (u16, Arc<Mutex<PathBuf>>)>>,
}

#[derive(serde::Deserialize, Serialize)]
struct SiteEntry {
    port: u16,
    cid: String,
}

fn sites_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(app.path().app_data_dir().map_err(|e| e.to_string())?.join("sites"))
}

fn valid_cid(c: &str) -> bool {
    c.len() >= 50 && c.len() <= 100 && c.starts_with('b') && c.chars().all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c))
}

fn load_site_map(dir: &Path) -> std::collections::BTreeMap<String, SiteEntry> {
    fs::read_to_string(dir.join("sites.json")).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

// Serve `name` from sites/<cid>/ at its own port (the one it had before, if it can)
fn serve_name(dir: &Path, sites: &Sites, name: &str, cid: &str) -> Result<u16, String> {
    let folder = dir.join(cid);
    let mut served = sites.served.lock().unwrap();
    if let Some((port, root)) = served.get(name) {
        *root.lock().unwrap() = folder;
        return Ok(*port);
    }
    let mut map = load_site_map(dir);
    let used: std::collections::HashSet<u16> = served.values().map(|(p, _)| *p).chain(map.iter().filter(|(n, _)| n.as_str() != name).map(|(_, e)| e.port)).collect();
    let mut port = map.get(name).map(|e| e.port).unwrap_or(0);
    let mut server = None;
    if port != 0 {
        server = tiny_http::Server::http(("127.0.0.1", port)).ok();
    }
    if server.is_none() {
        port = (FIRST_SITE_PORT..FIRST_SITE_PORT + 1000)
            .filter(|p| !used.contains(p))
            .find(|&p| { server = tiny_http::Server::http(("127.0.0.1", p)).ok(); server.is_some() })
            .ok_or("No free port for the site.")?;
    }
    let root = Arc::new(Mutex::new(folder));
    let r = root.clone();
    let server = server.unwrap();
    std::thread::spawn(move || serve_dir(server, r));
    served.insert(name.to_string(), (port, root));
    map.insert(name.to_string(), SiteEntry { port, cid: cid.to_string() });
    let _ = fs::write(dir.join("sites.json"), serde_json::to_string_pretty(&map).unwrap());
    Ok(port)
}

#[tauri::command]
fn site_kept(app: tauri::AppHandle, cid: String) -> bool {
    valid_cid(&cid) && sites_dir(&app).map(|d| d.join(&cid).join("index.html").is_file()).unwrap_or(false)
}

// One checked file of a site, as raw bytes; headers x-cid and x-path (percent-encoded) say which.
// Files go into sites/<cid>.part/ until site_open moves the whole site into place.
#[tauri::command]
fn site_put(app: tauri::AppHandle, request: tauri::ipc::Request<'_>) -> Result<(), String> {
    let tauri::ipc::InvokeBody::Raw(bytes) = request.body() else { return Err("expected the file's bytes".into()) };
    let h = |k: &str| request.headers().get(k).and_then(|v| v.to_str().ok()).map(str::to_string).ok_or(format!("missing {k}"));
    let cid = h("x-cid")?;
    let path = percent_decode(&h("x-path")?);
    if !valid_cid(&cid) {
        return Err("bad site address".into());
    }
    let parts: Vec<&str> = path.split('/').collect();
    if path.is_empty() || parts.iter().any(|p| p.is_empty() || *p == "." || *p == ".." || p.contains('\\') || p.contains(':')) {
        return Err("bad file name".into());
    }
    let file = sites_dir(&app)?.join(format!("{cid}.part")).join(&path);
    fs::create_dir_all(file.parent().unwrap()).map_err(|e| e.to_string())?;
    fs::write(&file, bytes).map_err(|e| e.to_string())
}

// Puts a downloaded site in place (if one was just sent) and serves `name` from it; returns its address
#[tauri::command]
fn site_open(app: tauri::AppHandle, sites: tauri::State<'_, Sites>, name: String, cid: String) -> Result<String, String> {
    if !valid_cid(&cid) || name.is_empty() || !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Err("bad name or site address".into());
    }
    let dir = sites_dir(&app)?;
    let part = dir.join(format!("{cid}.part"));
    let done = dir.join(&cid);
    if part.is_dir() {
        let _ = fs::remove_dir_all(&done);
        fs::rename(&part, &done).map_err(|e| e.to_string())?;
    }
    if !done.join("index.html").is_file() {
        return Err("The site isn't here yet.".into());
    }
    let port = serve_name(&dir, &sites, &name, &cid)?;
    // localhost rather than 127.0.0.1: browsers treat it as a secure origin, which wallets and passkeys need
    Ok(format!("http://localhost:{port}/"))
}

// At start: serve every name opened before, so its address keeps working
fn serve_known_sites(app: &tauri::AppHandle, sites: &Sites) {
    let Ok(dir) = sites_dir(app) else { return };
    for (name, e) in load_site_map(&dir) {
        if dir.join(&e.cid).join("index.html").is_file() {
            let _ = serve_name(&dir, sites, &name, &e.cid);
        }
    }
}

#[tauri::command]
fn site_url() -> String {
    // localhost rather than 127.0.0.1: browsers treat it as a secure origin, which wallets and
    // passkeys need. Reading goes through this computer's own node.
    format!("http://localhost:8790/?node={}", "http%3A%2F%2F127.0.0.1%3A8789")
}

#[tauri::command]
fn node_state(node: tauri::State<'_, Arc<Node>>) -> State {
    node.state.lock().unwrap().clone()
}

#[tauri::command]
fn open_data_folder(app: tauri::AppHandle, node: tauri::State<'_, Arc<Node>>) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    let dir = node.state.lock().unwrap().datadir.clone();
    app.opener().open_path(dir, None::<&str>).map_err(|e| e.to_string())
}

// off the main thread: a clean stop can take a while, and the window keeps updating meanwhile
#[tauri::command(async)]
fn restart(app: tauri::AppHandle, node: tauri::State<'_, Arc<Node>>) -> Result<(), String> {
    let node = node.inner().clone();
    stop(&node);
    *node.stopping.lock().unwrap() = false;
    start(&app, &node).map_err(|e| { node.set("failed", e.clone()); e })
}

// Adds a peer from the window: kept in added-peers.txt, then the node restarts to dial it
// off the main thread: a clean stop can take a while, and the window keeps updating meanwhile
#[tauri::command(async)]
fn add_peer(app: tauri::AppHandle, node: tauri::State<'_, Arc<Node>>, addr: String) -> Result<String, String> {
    let addr = addr.trim().to_string();
    if !valid_peer(&addr) {
        return Err("That isn't a peer's address. It looks like /ip4/1.2.3.4/tcp/17999/p2p/12D3Koo…".into());
    }
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?.join("node");
    let path = dir.join(ADDED_PEERS);
    let mut text = fs::read_to_string(&path).unwrap_or_default();
    if peer_lines(&text).any(|l| l == addr) || peer_lines(BOOTNODES).any(|l| l == addr) {
        return Ok("Your node already knows that peer.".into());
    }
    if text.is_empty() {
        text.push_str("# Peers added in the app's window, one per line. The node dials these at every start.\n");
    }
    text.push_str(&addr);
    text.push('\n');
    fs::write(&path, text).map_err(|e| format!("Can't save it: {e}"))?;
    let node = node.inner().clone();
    if node.state.lock().unwrap().phase == "elsewhere" {
        return Ok("Saved. The app's own node will use it when it runs.".into());
    }
    stop(&node);
    *node.stopping.lock().unwrap() = false;
    start(&app, &node).map_err(|e| { node.set("failed", e.clone()); e })?;
    Ok("Added. Your node restarted and is connecting to it.".into())
}

fn main() {
    let node = Arc::new(Node::default());
    let app = tauri::Builder::default()
        // one copy of the app: a second launch (on Windows, how a clicked web+csd: link arrives)
        // hands its link to the running one and quits. It must come first.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.set_focus();
            }
        }))
        // web+csd:<name> links, registered with the OS: the window looks the name up and opens it
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_autostart::init(tauri_plugin_autostart::MacosLauncher::LaunchAgent, None))
        .manage(node.clone())
        .manage(Sites::default())
        .invoke_handler(tauri::generate_handler![node_state, open_data_folder, restart, site_url, add_peer, site_kept, site_put, site_open])
        .setup({
            let node = node.clone();
            move |app| {
                // on Linux and Windows the scheme is registered at run time; macOS reads it from the bundle
                #[cfg(any(target_os = "linux", windows))]
                {
                    use tauri_plugin_deep_link::DeepLinkExt;
                    let _ = app.deep_link().register_all();
                }
                if let Err(e) = start(app.handle(), &node) {
                    node.set("failed", e);
                }
                if let Ok(dir) = app.path().resource_dir() {
                    let site = dir.join("commonplace");
                    if site.join("index.html").exists() {
                        std::thread::spawn(move || serve_site(site));
                    }
                }
                serve_known_sites(app.handle(), &app.state::<Sites>());
                Ok(())
            }
        })
        .on_window_event({
            let node = node.clone();
            move |window, event| {
                // Closing the window quits the app, but first the node stops cleanly; the window
                // stays up saying so until it has.
                if let WindowEvent::CloseRequested { api, .. } = event {
                    if node.child.lock().unwrap().is_some() {
                        api.prevent_close();
                        let node = node.clone();
                        let handle = window.app_handle().clone();
                        node.set("stopping", "Stopping the node…");
                        let _ = handle.emit("node-changed", ());
                        std::thread::spawn(move || {
                            stop(&node);
                            handle.exit(0);
                        });
                    }
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("the app failed to start");

    app.run(move |handle, event| match event {
        // Quit from the menu (Cmd-Q) or the system: the same clean stop before exiting, with the
        // window saying so
        RunEvent::ExitRequested { code: None, api, .. } if node.child.lock().unwrap().is_some() => {
            api.prevent_exit();
            node.set("stopping", "Stopping the node…");
            let _ = handle.emit("node-changed", ());
            let (node, handle) = (node.clone(), handle.clone());
            std::thread::spawn(move || {
                stop(&node);
                handle.exit(0);
            });
        }
        // and if the app ends any other way, still close the node's stdin and wait for it
        RunEvent::Exit => stop(&node),
        _ => {}
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_rebuild_from_the_log_as_it_grows() {
        let dir = std::env::temp_dir().join(format!("csd-app-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("node.log");
        fs::write(&p, "[tip] set_tip: old=0x00 -> new=0x01\n[reorg] recovery fallback: rebuilding state to tip 0xab\n[reorg] rebuild: replaying 4 blocks\n[tip] set_tip: old=0x00 -> new=0x01\n[tip] set_t").unwrap();
        let mut w = LogWatch::new(p.clone());
        w.update();
        assert!(w.rebuilding());
        assert_eq!((w.replayed, w.total), (1, Some(4)));
        assert_eq!(w.progress(), "Block 1 of 4 (25%).");
        use std::io::Write;
        let mut f = fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"ip: x\n[tip] set_tip: y\n[tip] set_tip: z\n").unwrap();
        w.update();
        assert_eq!(w.replayed, 4);
        assert!(!w.rebuilding());
        assert_eq!(group(143962), "143,962");
        assert!(peer_lines(BOOTNODES).all(valid_peer));
        assert!(valid_peer("/ip4/1.2.3.4/tcp/17999/p2p/12D3KooWHKcjL8M5snr3GniC8xRtGJGbGhPSdGiqtZNRz6UFj1t3"));
        assert!(valid_peer("/dns4/node.example.org/tcp/17999/p2p/12D3KooWHKcjL8M5snr3GniC8xRtGJGbGhPSdGiqtZNRz6UFj1t3"));
        assert!(!valid_peer("/ip4/1.2.3.4/tcp/17999/p2p/12D3KooWHKcjL8M5snr3GniC8xRtGJGbGhPSdGiqtZNRz6UFj1t3,/ip4/5.6.7.8"));
        assert!(!valid_peer("/ip4/1.2.3.4/tcp/17999"));
        assert!(!valid_peer("--rpc 0.0.0.0:8789"));
    }

    fn get(port: u16, path: &str) -> (u16, String) {
        use std::io::{Read, Write};
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(c, "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
        let mut out = String::new();
        c.read_to_string(&mut out).unwrap();
        let status = out[9..12].parse().unwrap();
        (status, out.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
    }

    #[test]
    fn serves_a_site_and_nothing_outside_it() {
        let dir = std::env::temp_dir().join(format!("csd-site-test-{}", std::process::id()));
        let site = dir.join("site");
        fs::create_dir_all(site.join("docs")).unwrap();
        fs::write(site.join("index.html"), "home").unwrap();
        fs::write(site.join("about.html"), "about").unwrap();
        fs::write(site.join("docs/index.html"), "docs").unwrap();
        fs::write(site.join("a b.txt"), "spaced").unwrap();
        fs::write(dir.join("secret.txt"), "secret").unwrap();
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let root = Arc::new(Mutex::new(site.clone()));
        let r = root.clone();
        std::thread::spawn(move || serve_dir(server, r));
        assert_eq!(get(port, "/"), (200, "home".into()));
        assert_eq!(get(port, "/about"), (200, "about".into()));
        assert_eq!(get(port, "/docs/"), (200, "docs".into()));
        assert_eq!(get(port, "/a%20b.txt"), (200, "spaced".into()));
        assert_eq!(get(port, "/../secret.txt").0, 404);
        assert_eq!(get(port, "/%2e%2e/secret.txt").0, 404);
        assert_eq!(get(port, "/nope").0, 404);
        fs::write(site.join("404.html"), "custom").unwrap();
        assert_eq!(get(port, "/nope"), (404, "custom".into()));
        // a newer site for the same name, same address
        let newer = dir.join("newer");
        fs::create_dir_all(&newer).unwrap();
        fs::write(newer.join("index.html"), "v2").unwrap();
        *root.lock().unwrap() = newer;
        assert_eq!(get(port, "/"), (200, "v2".into()));
        assert!(valid_cid("bafybeifg5gfnjgvl6djmhuk2rpbtkmgylcqn4aybevi6skkinflpbbfs44"));
        assert!(!valid_cid("../bafybeifg5gfnjgvl6djmhuk2rpbtkmgylcqn4aybevi6skkinflpbbfs"));
        fs::remove_dir_all(&dir).ok();
        fs::remove_dir_all(&dir).ok();
    }
}
