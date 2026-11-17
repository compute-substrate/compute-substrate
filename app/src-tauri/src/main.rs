// Compute Substrate, the app: runs the `csd` node that ships inside it, on this computer, with no
// terminal. It keeps the node's data in the app's own folder, starts it when the app opens and stops
// it cleanly when the app closes. The window shows how far the node has synced; apps on this
// computer (and web pages in its browser) can use the node at http://127.0.0.1:8789.
//
// The node is the same program an operator builds from this repository. The app only starts it,
// with these arguments, and watches it.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::Serialize;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
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
// way out; a stop during startup recovery waits for the rebuild to finish first.
const STOP_WAIT: Duration = Duration::from_secs(120);

#[derive(Clone, Serialize, Default)]
struct State {
    /// starting | running | elsewhere | stopping | stopped | failed
    phase: String,
    message: String,
    rpc: String,
    datadir: String,
}

#[derive(Default)]
struct Node {
    child: Mutex<Option<Child>>,
    state: Mutex<State>,
    stopping: Mutex<bool>,
}

impl Node {
    fn set(&self, phase: &str, message: impl Into<String>) {
        let mut s = self.state.lock().unwrap();
        s.phase = phase.into();
        s.message = message.into();
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
    node.set("starting", "Starting the node…");

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
                if phase == "starting" && answers(RPC) {
                    n.set("running", "");
                    let _ = handle.emit("node-changed", ());
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
    while t.elapsed() < STOP_WAIT {
        if let Ok(Some(_)) = child.try_wait() {
            node.set("stopped", "");
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let _ = child.kill();
    let _ = child.wait();
    node.set("stopped", "");
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
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_autostart::init(tauri_plugin_autostart::MacosLauncher::LaunchAgent, None))
        .manage(node.clone())
        .invoke_handler(tauri::generate_handler![node_state, open_data_folder, restart])
        .setup({
            let node = node.clone();
            move |app| {
                if let Err(e) = start(app.handle(), &node) {
                    node.set("failed", e);
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
