// Which node the explorer reads. No server of its own: it asks the network's doors directly (any
// door serves the same read-only API), the most up to date first, and the next if one stops
// answering. Opened in Doorway (explorer.localhost), this computer's own node once it has caught
// up. ?node=https://… reads through that node only.
(function () {
  const DOORS = ["https://csd.aon.network", "https://151-240-121-186.sslip.io", "https://151-240-121-187.sslip.io"];
  const OWN = "http://127.0.0.1:8789";
  const asked = new URLSearchParams(location.search).get("node");
  const tipOf = async base => {
    try {
      const r = await fetch(base + "/tip", { signal: AbortSignal.timeout(4000) });
      const j = r.ok ? await r.json() : null;
      return Number.isSafeInteger(j?.height) ? j.height : -1;
    } catch { return -1; }
  };
  let ranked = null;
  function rank() {
    if (asked) return Promise.resolve([asked.replace(/\/+$/, "")]);
    const list = [...(location.hostname.endsWith(".localhost") ? [OWN] : []), ...DOORS];
    return Promise.all(list.map(async b => ({ b, h: await tipOf(b) }))).then(r => {
      const up = r.filter(x => x.h >= 0).sort((a, b) => b.h - a.h);
      return (up.length ? up : r).map(x => x.b);
    });
  }
  // like fetch(path), from the best node, falling back to the next
  window.csdFetch = async (path, opts) => {
    ranked ??= rank();
    let last;
    for (const b of await ranked) {
      try { const r = await fetch(b + path, opts); if (r.status < 500) return r; last = new Error(`${path} → HTTP ${r.status}`); }
      catch (e) { last = e; }
    }
    throw last ?? new Error("No node answered.");
  };
  window.csdDoors = DOORS;
  window.csdReading = () => (ranked ??= rank()).then(l => l[0]);
})();
