// Keeping a page from the ordinary web: Doorway opens it in a window of its own, hidden and private
// (no cookies, nothing signed in, so what's kept is the page anyone would see, never your inbox),
// lets it load, and saves it as it stands: one HTML file with no scripts (capture.js, run in the
// page), plus its pictures, styles and fonts, fetched here and given local names. The main window
// packs that as a site, which is then kept like any other.
use std::collections::HashMap;
use std::io::Read;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{mpsc, Mutex};
use std::time::Duration;
use tauri::webview::PageLoadEvent;
use tauri::{Emitter, WebviewUrl, WebviewWindowBuilder};

const SERIALIZE: &str = include_str!("capture.js");
// scrolls down the page and back, so pictures that load only once they're scrolled to do
const SCROLL: &str = "(() => { const h = Math.min(Math.max(document.documentElement.scrollHeight || 0, 2000), 40000); let y = 0; const step = () => { y += 800; window.scrollTo(0, y); if (y < h) setTimeout(step, 100); else setTimeout(() => window.scrollTo(0, 0), 400); }; step(); return true; })()";
const UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15 Doorway";
const MAX_FILES: usize = 600;
const MAX_ONE: usize = 8 * 1024 * 1024;
const MAX_TOTAL: usize = 30 * 1024 * 1024;
const MAX_HTML: usize = 10 * 1024 * 1024;
const WAVES: usize = 4; // a stylesheet's import's font, and so on
const MISSING: &str = "data:,";

static N: AtomicU32 = AtomicU32::new(0);
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

// Addresses on this computer or a home network: not pages anyone else could check, and not for a
// page to point Doorway at
pub fn is_private(url: &tauri::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(h)) => {
            let h = h.to_ascii_lowercase();
            h == "localhost" || h.ends_with(".localhost") || h.ends_with(".local") || h.ends_with(".internal") || !h.contains('.')
        }
        Some(url::Host::Ipv4(ip)) => ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() || (ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1])),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback() || ip.is_unspecified() || (ip.segments()[0] & 0xfe00) == 0xfc00 || (ip.segments()[0] & 0xffc0) == 0xfe80,
        None => true,
    }
}

// The page saved as it stands, with its pictures, styles and fonts: files for a site, sent to the
// window as [u32 header length][header JSON][the files' bytes, one after another]
#[tauri::command]
pub async fn page_capture(app: tauri::AppHandle, url: String) -> Result<tauri::ipc::Response, String> {
    let u: tauri::Url = url.trim().parse().map_err(|_| "That isn't a web address.".to_string())?;
    if u.scheme() != "https" && u.scheme() != "http" {
        return Err("Only web pages (http and https) can be kept.".into());
    }
    if is_private(&u) {
        return Err("That's a page on this computer or your own network, so nobody else could check a copy of it.".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        capture(&app, u)
    })
    .await
    .map_err(|e| e.to_string())?
    .map(tauri::ipc::Response::new)
}

struct Snapshot {
    url: String,
    title: String,
    html: String,
    res: Vec<String>,
}

fn step(app: &tauri::AppHandle, s: &str) {
    let _ = app.emit("keep-step", s);
}

fn snapshot(app: &tauri::AppHandle, url: tauri::Url) -> Result<Snapshot, String> {
    let label = format!("keep-{}", N.fetch_add(1, Ordering::SeqCst));
    let (loaded, wait) = mpsc::channel::<()>();
    let loaded = Mutex::new(loaded);
    step(app, "Opening it in a private window…");
    let win = WebviewWindowBuilder::new(app, &label, WebviewUrl::External(url))
        .title("Keeping a page")
        .visible(false)
        .focused(false)
        .skip_taskbar(true)
        .inner_size(1280.0, 1000.0)
        .incognito(true)
        // never on to this computer or the home network, even if the page sends it there
        .on_navigation(|u| (u.scheme() == "https" || u.scheme() == "http") && !is_private(u))
        .on_page_load(move |_, p| {
            if p.event() == PageLoadEvent::Finished {
                let _ = loaded.lock().unwrap().send(());
            }
        })
        .build()
        .map_err(|e| format!("Couldn't open the page: {e}"))?;
    let result = (|| {
        if wait.recv_timeout(Duration::from_secs(45)).is_err() {
            step(app, "It's slow to load. Keeping what has loaded so far…");
        }
        // let it settle (a redirect, a page that fills itself in), then scroll through it once
        std::thread::sleep(Duration::from_millis(2500));
        while wait.try_recv().is_ok() {}
        step(app, "Letting it load everything…");
        let _ = win.eval(SCROLL);
        std::thread::sleep(Duration::from_millis(4500));
        step(app, "Saving it as it stands…");
        let (said, answer) = mpsc::channel::<String>();
        let said = Mutex::new(said);
        win.eval_with_callback(SERIALIZE, move |s| {
            let _ = said.lock().unwrap().send(s);
        })
        .map_err(|e| e.to_string())?;
        let raw = answer.recv_timeout(Duration::from_secs(40)).map_err(|_| "The page didn't let itself be saved in time.".to_string())?;
        let mut v: serde_json::Value = serde_json::from_str(&raw).map_err(|_| "The page couldn't be saved.".to_string())?;
        if let Some(s) = v.as_str() {
            v = serde_json::from_str(s).unwrap_or(serde_json::Value::Null);
        }
        if v["ok"].as_bool() != Some(true) {
            return Err(format!("The page couldn't be saved: {}", v["error"].as_str().unwrap_or("it gave nothing back")));
        }
        let html = v["html"].as_str().unwrap_or("").to_string();
        if html.len() > MAX_HTML {
            return Err("That page is too large to keep.".into());
        }
        Ok(Snapshot {
            url: v["url"].as_str().unwrap_or("").to_string(),
            title: v["title"].as_str().unwrap_or("").chars().take(300).collect(),
            html,
            res: v["res"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default(),
        })
    })();
    let _ = win.destroy();
    result
}

fn capture(app: &tauri::AppHandle, url: tauri::Url) -> Result<Vec<u8>, String> {
    let snap = snapshot(app, url)?;
    step(app, &format!("Saving its pictures and styles ({})…", snap.res.len()));
    let got = fetch_all(&snap.res);
    let mut files: Vec<(String, Vec<u8>)> = vec![];
    let html = replace_placeholders(&snap.html, |i| got.names.get(&i).map(|n| format!("r/{n}")));
    files.push(("index.html".into(), html.into_bytes()));
    for (n, bytes) in got.files {
        files.push((format!("r/{n}"), bytes));
    }
    let header = serde_json::json!({
        "url": snap.url,
        "title": snap.title,
        "files": files.iter().map(|(p, b)| serde_json::json!({ "path": p, "size": b.len() })).collect::<Vec<_>>(),
        "missing": got.missing,
    })
    .to_string();
    let mut out = Vec::with_capacity(4 + header.len() + files.iter().map(|f| f.1.len()).sum::<usize>());
    out.extend((header.len() as u32).to_le_bytes());
    out.extend(header.as_bytes());
    for (_, b) in files {
        out.extend(b);
    }
    Ok(out)
}

struct Fetched {
    names: HashMap<usize, String>, // placeholder number -> its file's name, under r/
    files: Vec<(String, Vec<u8>)>,
    missing: usize,
}

// Everything the page listed, and what its stylesheets name in turn, fetched (eight at a time, like
// a browser), within the limits. What couldn't be fetched is left out of the copy rather than loaded
// from the live web, which would show whatever is there now, and tell the site who's looking.
fn fetch_all(first: &[String]) -> Fetched {
    let mut urls: Vec<String> = first.to_vec();
    let mut index: HashMap<String, usize> = urls.iter().enumerate().map(|(i, u)| (u.clone(), i)).collect();
    let mut bodies: HashMap<usize, (Vec<u8>, String)> = HashMap::new();
    let mut total = 0usize;
    let mut wave: Vec<usize> = (0..urls.len().min(MAX_FILES)).collect();
    for _ in 0..WAVES {
        if wave.is_empty() {
            break;
        }
        let queue = Mutex::new(wave.clone());
        let done = Mutex::new(Vec::<(usize, Vec<u8>, String)>::new());
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| loop {
                    let Some(i) = queue.lock().unwrap().pop() else { break };
                    if let Some((b, ct)) = fetch(&urls[i]) {
                        done.lock().unwrap().push((i, b, ct));
                    }
                });
            }
        });
        let mut next = vec![];
        for (i, b, ct) in done.into_inner().unwrap() {
            if total + b.len() > MAX_TOTAL {
                continue;
            }
            total += b.len();
            let ext = ext_of(&ct, &urls[i], &b);
            if ext == "css" {
                // its own pictures, fonts and imports, named for the next wave
                let base = urls[i].clone();
                let css = rewrite_css(&String::from_utf8_lossy(&b), |rel| {
                    let abs = tauri::Url::parse(&base).ok()?.join(rel.trim()).ok()?;
                    if abs.scheme() != "https" && abs.scheme() != "http" {
                        return None;
                    }
                    let abs = abs.to_string();
                    let n = match index.get(&abs) {
                        Some(&n) => n,
                        None if urls.len() < MAX_FILES => {
                            urls.push(abs.clone());
                            index.insert(abs, urls.len() - 1);
                            next.push(urls.len() - 1);
                            urls.len() - 1
                        }
                        None => return None,
                    };
                    Some(n)
                });
                bodies.insert(i, (css.into_bytes(), ext.into()));
            } else {
                bodies.insert(i, (b, ext.into()));
            }
        }
        wave = next;
    }
    let names: HashMap<usize, String> = bodies.iter().map(|(i, (_, ext))| (*i, format!("{i}.{ext}"))).collect();
    let mut files = vec![];
    for (i, (b, ext)) in bodies {
        let b = if ext == "css" { replace_placeholders(&String::from_utf8_lossy(&b), |j| names.get(&j).cloned()).into_bytes() } else { b };
        files.push((format!("{i}.{ext}"), b));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Fetched { missing: urls.len() - names.len(), names, files }
}

fn fetch(url: &str) -> Option<(Vec<u8>, String)> {
    // a page can name anything; what's on this computer or the home network never goes into a copy
    let private = |u: &str| !cfg!(test) && u.parse::<tauri::Url>().map(|u| is_private(&u)).unwrap_or(true);
    if private(url) {
        return None;
    }
    let r = ureq::get(url).set("User-Agent", UA).set("Accept", "*/*").timeout(Duration::from_secs(20)).call().ok()?;
    if private(r.get_url()) {
        return None; // sent on there by a redirect
    }
    let ct = r.header("content-type").unwrap_or("").to_ascii_lowercase();
    let mut b = vec![];
    r.into_reader().take(MAX_ONE as u64 + 1).read_to_end(&mut b).ok()?;
    (b.len() <= MAX_ONE).then_some((b, ct))
}

// A file's kind, from what the server said, else its name, else its first bytes
fn ext_of(ct: &str, url: &str, b: &[u8]) -> &'static str {
    let t = ct.split(';').next().unwrap_or("").trim();
    let by_type = match t {
        "text/css" => "css",
        "image/png" => "png",
        "image/jpeg" | "image/jpg" | "image/pjpeg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/avif" => "avif",
        "image/svg+xml" => "svg",
        "image/x-icon" | "image/vnd.microsoft.icon" => "ico",
        "font/woff2" | "application/font-woff2" | "application/x-font-woff2" => "woff2",
        "font/woff" | "application/font-woff" | "application/x-font-woff" => "woff",
        "font/ttf" | "application/x-font-ttf" | "font/sfnt" | "application/x-font-truetype" => "ttf",
        "font/otf" | "application/x-font-opentype" => "otf",
        _ => "",
    };
    if !by_type.is_empty() {
        return by_type;
    }
    let path = url.split(['?', '#']).next().unwrap_or("").to_ascii_lowercase();
    for e in ["css", "png", "jpg", "jpeg", "gif", "webp", "avif", "svg", "ico", "woff2", "woff", "ttf", "otf"] {
        if path.ends_with(&format!(".{e}")) {
            return if e == "jpeg" { "jpg" } else { e };
        }
    }
    match b {
        [0x89, b'P', b'N', b'G', ..] => "png",
        [0xff, 0xd8, ..] => "jpg",
        [b'G', b'I', b'F', b'8', ..] => "gif",
        [b'R', b'I', b'F', b'F', _, _, _, _, b'W', b'E', b'B', b'P', ..] => "webp",
        [b'w', b'O', b'F', b'2', ..] => "woff2",
        [b'w', b'O', b'F', b'F', ..] => "woff",
        _ if String::from_utf8_lossy(&b[..b.len().min(256)]).contains("<svg") => "svg",
        _ => "bin",
    }
}

// url(…) and @import in a stylesheet, each given a placeholder by `name` (or left as it was)
fn rewrite_css(css: &str, mut name: impl FnMut(&str) -> Option<usize>) -> String {
    let mut out = String::with_capacity(css.len());
    let mut rest = css;
    loop {
        let lower = rest.to_ascii_lowercase();
        let (u, i) = (lower.find("url("), lower.find("@import"));
        let at = match (u, i) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => break,
        };
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        if rest[..4].eq_ignore_ascii_case("url(") {
            let Some(end) = rest.find(')') else { break };
            let inner = rest[4..end].trim().trim_matches(['"', '\'']);
            match (!inner.is_empty() && !inner.starts_with("data:") && !inner.starts_with('#')).then(|| name(inner)).flatten() {
                Some(n) => out.push_str(&format!("url(\"__csdkeep_{n}__\")")),
                None => out.push_str(&rest[..=end]),
            }
            rest = &rest[end + 1..];
        } else {
            // @import "x.css" (the url(…) form is handled above, as a url)
            let after = &rest[7..];
            let t = after.trim_start();
            let q = t.chars().next();
            if let Some(q @ ('"' | '\'')) = q {
                if let Some(close) = t[1..].find(q) {
                    let inner = &t[1..1 + close];
                    let skip = 7 + (after.len() - t.len()) + close + 2;
                    match name(inner) {
                        Some(n) => out.push_str(&format!("@import \"__csdkeep_{n}__\"")),
                        None => out.push_str(&rest[..skip]),
                    }
                    rest = &rest[skip..];
                    continue;
                }
            }
            out.push_str(&rest[..7]);
            rest = &rest[7..];
        }
    }
    out.push_str(rest);
    out
}

// __csdkeep_<n>__ swapped for its file's name, or for nothing (data:,) where it couldn't be fetched
fn replace_placeholders(text: &str, name: impl Fn(usize) -> Option<String>) -> String {
    const P: &str = "__csdkeep_";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(P) {
        out.push_str(&rest[..at]);
        let after = &rest[at + P.len()..];
        let digits = after.chars().take_while(|c| c.is_ascii_digit()).count();
        if digits > 0 && after[digits..].starts_with("__") {
            let n: usize = after[..digits].parse().unwrap_or(usize::MAX);
            out.push_str(&name(n).unwrap_or_else(|| MISSING.into()));
            rest = &after[digits + 2..];
        } else {
            out.push_str(P);
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stylesheets_name_what_they_load() {
        let mut seen = vec![];
        let css = r#"@import "a.css"; body{background:url(img/b.png)} @font-face{src:url('f.woff2') format("woff2"), url(data:font/x;base64,AA)} .x{background:URL( "c.svg" )} a{content:"@import"}"#;
        let out = rewrite_css(css, |u| { seen.push(u.to_string()); Some(seen.len() - 1) });
        assert_eq!(seen, vec!["a.css", "img/b.png", "f.woff2", "c.svg"]);
        assert!(out.contains(r#"@import "__csdkeep_0__""#) && out.contains(r#"url("__csdkeep_1__")"#) && out.contains("url(data:font/x;base64,AA)") && out.contains(r#"url("__csdkeep_3__")"#));
        assert!(out.ends_with(r#"a{content:"@import"}"#));
    }

    #[test]
    fn placeholders_become_files_or_nothing() {
        let t = r#"<img src="__csdkeep_0__"><img src="__csdkeep_7__"> __csdkeep_x__ __csdkeep_12"#;
        let out = replace_placeholders(t, |n| (n == 0).then(|| "r/0.png".to_string()));
        assert_eq!(out, r#"<img src="r/0.png"><img src="data:,"> __csdkeep_x__ __csdkeep_12"#);
    }

    #[test]
    fn kinds_of_files() {
        assert_eq!(ext_of("text/css; charset=utf-8", "https://x/a", b""), "css");
        assert_eq!(ext_of("application/octet-stream", "https://x/f.WOFF2?v=3", b""), "woff2");
        assert_eq!(ext_of("", "https://x/pic", &[0x89, b'P', b'N', b'G', 0]), "png");
        assert_eq!(ext_of("", "https://x/thing", b"<?xml?><svg/>"), "svg");
    }

    #[test]
    fn a_page_and_what_its_stylesheets_load() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        std::thread::spawn(move || {
            for req in server.incoming_requests() {
                let (ct, body): (&str, Vec<u8>) = match req.url() {
                    "/css/main.css" => ("text/css", b"@import 'extra.css'; .a{background:url(../img/bg.png)} @font-face{src:url(/f.woff2)}".to_vec()),
                    "/css/extra.css" => ("text/css", b".b{background:url(deep.gif)}".to_vec()),
                    "/img/bg.png" => ("image/png", vec![0x89, b'P', b'N', b'G']),
                    "/css/deep.gif" => ("", b"GIF89a".to_vec()),
                    "/f.woff2" => ("font/woff2", b"wOF2".to_vec()),
                    "/huge.png" => ("image/png", vec![0; MAX_ONE + 10]),
                    _ => ("", vec![]),
                };
                let mut r = tiny_http::Response::from_data(body).with_status_code(if ct.is_empty() && !req.url().ends_with(".gif") { 404 } else { 200 });
                if !ct.is_empty() { r = r.with_header(tiny_http::Header::from_bytes(&b"Content-Type"[..], ct.as_bytes()).unwrap()); }
                let _ = req.respond(r);
            }
        });
        let base = format!("http://127.0.0.1:{port}");
        let got = fetch_all(&[format!("{base}/css/main.css"), format!("{base}/nope.png"), format!("{base}/huge.png")]);
        let file = |p: &str| got.files.iter().find(|f| f.0 == p).map(|f| String::from_utf8_lossy(&f.1).to_string());
        assert_eq!(got.names.get(&0).map(String::as_str), Some("0.css"));
        let main = file("0.css").unwrap();
        // its import, its picture and its font: fetched, and named by their local copies
        assert!(main.contains("@import \"3.css\"") && main.contains("url(\"4.png\")") && main.contains("url(\"5.woff2\")"), "{main}");
        assert!(file("3.css").unwrap().contains("url(\"6.gif\")"), "an import's own picture, a wave later");
        assert_eq!(file("6.gif").as_deref(), Some("GIF89a"));
        assert!(!got.names.contains_key(&1) && !got.names.contains_key(&2), "what couldn't be had, or is too large, is left out");
        assert_eq!(got.missing, 2);
        let html = replace_placeholders("<img src=\"__csdkeep_1__\"><link href=\"__csdkeep_0__\">", |i| got.names.get(&i).map(|n| format!("r/{n}")));
        assert_eq!(html, "<img src=\"data:,\"><link href=\"r/0.css\">");
    }

    #[test]
    fn home_and_local_addresses_are_refused() {
        for u in ["http://localhost:3000/", "http://192.168.1.1/", "http://10.1.2.3/", "http://router/", "http://[::1]/", "http://x.localhost/", "http://100.100.1.1/"] {
            assert!(is_private(&u.parse().unwrap()), "{u}");
        }
        for u in ["https://www.nytimes.com/a", "https://1.1.1.1/"] {
            assert!(!is_private(&u.parse().unwrap()), "{u}");
        }
    }
}
