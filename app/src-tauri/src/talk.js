// The conversation beside a kept copy: added by Doorway to the copies it serves (never part of the
// copy itself). It reads and posts through Doorway (POST /.doorway/talk), which reads the network,
// checks names, and asks the person before anything is posted. Drawn in its own shadow root, so the
// page's styles and its own don't touch.
(() => {
  if (window.__csdTalk) return;
  window.__csdTalk = true;
  const ask = body => fetch("/.doorway/talk", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })
    .then(async r => { const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || `Doorway answered ${r.status}`); return j; });
  const esc = t => String(t).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const tint = a => { let h = 0; for (const ch of a) h = (h * 31 + ch.charCodeAt(0)) >>> 0; return `hsl(${h % 360} 45% 52%)`; };
  const here = location.hostname.split(".")[0];
  const copyUrl = cid => `${location.protocol}//${cid}.${location.host.split(".").slice(1).join(".")}/`;
  const ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12a8 8 0 0 1-11.6 7.1L4 20l1-4.6A8 8 0 1 1 21 12z"/></svg>';
  const X = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18"/></svg>';

  const host = document.createElement("div");
  host.style.cssText = "all:initial;position:fixed;z-index:2147483647;inset:auto 0 0 auto";
  const root = host.attachShadow({ mode: "open" });
  root.innerHTML = `<style>
    :host { all: initial; }
    * { box-sizing: border-box; }
    .w { --bg:#fbf7f0; --card:#fff; --ink:#2a2420; --muted:#8a8078; --line:#efe7db; --accent:#2e6b5a; --soft:#e3efe9; --on:#fff;
         font: 14px/1.5 ui-rounded, "SF Pro Rounded", -apple-system, "Segoe UI", system-ui, sans-serif; color: var(--ink); }
    @media (prefers-color-scheme: dark) { .w { --bg:#1a1714; --card:#24201c; --ink:#f2ece4; --muted:#a59a8e; --line:#332d27; --accent:#7fcbb0; --soft:#23352e; --on:#10201b; } }
    button { font: inherit; cursor: pointer; }
    .open { position: fixed; right: 18px; bottom: 18px; display: inline-flex; align-items: center; gap: 8px; border: 0; border-radius: 999px; padding: 11px 16px; background: var(--accent); color: var(--on); font-weight: 650; box-shadow: 0 6px 24px rgba(0,0,0,.22); }
    .open svg { width: 17px; height: 17px; }
    .open .n { background: rgba(255,255,255,.25); border-radius: 999px; padding: 0 7px; font-size: 12px; }
    .panel { position: fixed; top: 0; right: 0; height: 100vh; width: min(380px, 100vw); background: var(--card); border-left: 1px solid var(--line); box-shadow: -10px 0 40px rgba(0,0,0,.18); display: flex; flex-direction: column; }
    .head { padding: 16px 18px 12px; border-bottom: 1px solid var(--line); display: flex; gap: 10px; align-items: flex-start; }
    .head div { flex: 1; min-width: 0; }
    .head b { font-weight: 700; font-size: 16px; display: block; }
    .head small { color: var(--muted); font-size: 12px; display: block; margin-top: 2px; }
    .x { border: 0; background: transparent; color: var(--muted); padding: 4px; border-radius: 8px; display: grid; }
    .x:hover { background: var(--bg); color: var(--ink); }
    .x svg { width: 18px; height: 18px; }
    .list { flex: 1; overflow-y: auto; padding: 6px 18px; }
    .c { display: flex; gap: 10px; padding: 12px 0; border-bottom: 1px solid var(--line); }
    .c:last-child { border-bottom: 0; }
    .av { width: 30px; height: 30px; border-radius: 50%; display: grid; place-items: center; color: #fff; font-weight: 700; font-size: 13px; flex: none; }
    .av.q { background: var(--line); color: var(--muted); }
    .body { flex: 1; min-width: 0; }
    .top { display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap; }
    .who { font-weight: 650; }
    .who.no { font-style: italic; font-weight: 450; color: var(--muted); }
    .tag { font-size: 10.5px; font-weight: 600; color: var(--muted); border: 1px solid var(--line); border-radius: 999px; padding: 0 6px; }
    .when { color: var(--muted); font-size: 12px; }
    .text { white-space: pre-wrap; overflow-wrap: anywhere; margin-top: 2px; user-select: text; -webkit-user-select: text; }
    .meta { margin-top: 4px; display: flex; gap: 12px; font-size: 12px; }
    .meta a, .meta button { color: var(--muted); background: none; border: 0; padding: 0; text-decoration: underline; text-underline-offset: 2px; font-size: 12px; }
    .meta button { visibility: hidden; }
    .c:hover .meta button { visibility: visible; }
    .empty { color: var(--muted); text-align: center; padding: 40px 10px; font-size: 13px; }
    .say { border-top: 1px solid var(--line); padding: 12px 18px 16px; display: flex; flex-direction: column; gap: 8px; background: var(--card); }
    textarea { font: inherit; color: var(--ink); background: var(--bg); border: 1px solid var(--line); border-radius: 12px; padding: 10px 12px; min-height: 84px; resize: vertical; outline: none; }
    textarea:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--soft); }
    .row { display: flex; align-items: center; gap: 10px; }
    .row span { flex: 1; color: var(--muted); font-size: 12px; }
    .post { border: 0; border-radius: 10px; padding: 8px 16px; background: var(--accent); color: var(--on); font-weight: 650; }
    .post:disabled { opacity: .55; cursor: default; }
    .said { font-size: 12px; color: var(--muted); min-height: 1em; }
    [hidden] { display: none !important; }
  </style>
  <div class="w">
    <button class="open" id="open">${ICON}<span>Conversation</span><span class="n" id="n" hidden></span></button>
    <aside class="panel" id="panel" hidden aria-label="Conversation">
      <div class="head"><div><b>Conversation</b><small id="about">About this page. Anyone with Doorway can join in, and nobody can delete what's said.</small></div><button class="x" id="close" aria-label="Close">${X}</button></div>
      <div class="list" id="list"><div class="empty">Reading the conversation…</div></div>
      <div class="say">
        <textarea id="text" placeholder="Say something about this page…"></textarea>
        <div class="row"><span id="room"></span><button class="post" id="post">Post</button></div>
        <div class="said" id="said"></div>
      </div>
    </aside>
  </div>`;
  const $ = id => root.getElementById(id);
  let kept = null, room = 440, timer = 0, mine = "";

  function draw(r) {
    mine = r.me || "";
    room = r.room || room;
    const n = r.said.length;
    $("n").hidden = !n; $("n").textContent = String(n);
    $("about").textContent = `About ${r.page}. Anyone with Doorway can join in, and nobody can delete what's said.`;
    $("list").innerHTML = n ? r.said.map(s => `<div class="c">
        ${s.name ? `<span class="av" style="background:${tint(s.by)}">${esc(s.name[0].toUpperCase())}</span>` : `<span class="av q">?</span>`}
        <div class="body"><div class="top">${s.name ? `<span class="who">${esc(s.name)}</span>` : `<span class="who no">${esc(s.friendly)}</span><span class="tag">no name</span>`}<span class="when">${esc(s.when)}</span></div>
          <div class="text">${esc(s.text)}</div>
          <div class="meta">${s.copy !== here ? `<a href="${esc(copyUrl(s.copy))}">${s.copyWhen ? `on the copy from ${esc(s.copyWhen)}` : "on another copy"}</a>` : ""}${s.by !== mine ? `<button data-mute="${esc(s.by)}">Mute</button>` : ""}</div></div></div>`).join("")
      : `<div class="empty">Nobody has said anything about this page yet.</div>`;
    root.querySelectorAll("[data-mute]").forEach(b => b.onclick = async () => { await ask({ mute: b.dataset.mute }).catch(() => {}); load(); });
    count();
  }
  async function load() {
    if (!kept) return;
    try { draw(await ask({ read: true, url: kept.url })); }
    catch (e) { $("list").innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
  }
  const count = () => { const left = room - new TextEncoder().encode($("text").value.trim()).length; $("room").textContent = left < 0 ? `${-left} too many` : left < 80 ? `${left} left` : "A post's worth"; $("post").disabled = left < 0 || !$("text").value.trim(); };
  $("text").oninput = count;
  $("open").onclick = () => { $("panel").hidden = false; $("open").hidden = true; load(); clearInterval(timer); timer = setInterval(load, 60_000); };
  $("close").onclick = () => { $("panel").hidden = true; $("open").hidden = false; clearInterval(timer); };
  $("post").onclick = async () => {
    const text = $("text").value.trim();
    if (!text) return;
    $("post").disabled = true; $("text").readOnly = true; $("said").textContent = "Doorway is asking you…";
    try {
      await ask({ text, url: kept.url });
      $("text").value = ""; $("said").textContent = "Posted. It shows here in a minute or two.";
      setTimeout(load, 90_000); setTimeout(load, 150_000);
    } catch (e) { $("said").textContent = e.message; }
    $("text").readOnly = false; count();
  };
  fetch("/kept.json").then(r => r.ok ? r.json() : null).then(k => {
    if (!k || !k.url) return;
    kept = k;
    document.documentElement.appendChild(host);
    ask({ read: true, url: k.url }).then(draw).catch(() => {});
  }).catch(() => {});
})();
