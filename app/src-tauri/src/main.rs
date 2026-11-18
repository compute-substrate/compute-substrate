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
// way out. A stop during a rebuild (below) is never cut short: the node finishes the rebuild first,
// and killing it then would only make the next start rebuild again from the beginning.
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

// What the node is doing while it starts, read from its log as the log grows. After a stop that
// wasn't clean (the computer lost power, the app was force-quit), the node rebuilds its copy of the
// network's state from the blocks it already has, before it answers anyone: one `[tip] set_tip`
// line per block, after a `[reorg] recovery fallback` line (and, from newer nodes, a line with the
// number of blocks).
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

fn bootnodes() -> String {
    BOOTNODES
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join(",")
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
    let boot = bootnodes();
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
                                "It wasn't stopped cleanly last time, so it's rebuilding its copy from the blocks it already has. This can take a while; leave the app open until it's done.\n\n{}",
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
        if w.rebuilding() {
            node.set_rebuild("stopping", format!("Finishing its rebuild first, so the next start doesn't have to begin it again.\n\n{}", w.progress()), &w);
        } else if t.elapsed() >= STOP_WAIT {
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

fn serve_site(root: PathBuf) {
    let server = match tiny_http::Server::http(LOCAL_SITE) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[site] can't serve Commonplace on {LOCAL_SITE}: {e}");
            return;
        }
    };
    let Ok(root) = root.canonicalize() else { return };
    for req in server.incoming_requests() {
        let path = req.url().split(['?', '#']).next().unwrap_or("/").to_string();
        let rel = path.trim_start_matches('/');
        let mut file = root.join(if rel.is_empty() { "index.html" } else { rel });
        if file.is_dir() {
            file = file.join("index.html");
        }
        // only files inside the release, nothing else on this computer
        let ok = file.canonicalize().map(|f| f.starts_with(&root)).unwrap_or(false);
        let resp = if ok {
            match fs::read(&file) {
                Ok(bytes) => tiny_http::Response::from_data(bytes)
                    .with_header(tiny_http::Header::from_bytes(&b"Content-Type"[..], mime(&file.to_string_lossy()).as_bytes()).unwrap())
                    .with_status_code(200),
                Err(_) => tiny_http::Response::from_data(b"not found".to_vec()).with_status_code(404),
            }
        } else {
            tiny_http::Response::from_data(b"not found".to_vec()).with_status_code(404)
        };
        let _ = req.respond(resp);
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

#[tauri::command]
fn restart(app: tauri::AppHandle, node: tauri::State<'_, Arc<Node>>) -> Result<(), String> {
    let node = node.inner().clone();
    stop(&node);
    *node.stopping.lock().unwrap() = false;
    start(&app, &node).map_err(|e| { node.set("failed", e.clone()); e })
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
        .invoke_handler(tauri::generate_handler![node_state, open_data_folder, restart, site_url])
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
        fs::remove_dir_all(&dir).ok();
    }
}
