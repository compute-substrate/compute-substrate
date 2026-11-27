// Run in the page being kept, in Doorway's private window, once it has loaded: turns the page as it
// stands into one HTML file with no scripts, and lists what it needs (pictures, styles, fonts), each
// replaced in the HTML by a placeholder, __csdkeep_<n>__, that Doorway swaps for its own copy. Links
// stay links to the live web. It returns an object (Doorway reads it as JSON); it never throws.
(() => {
  try {
    const res = [], seen = new Map();
    const put = raw => {
      let u;
      try { u = new URL(String(raw).trim(), document.baseURI).href; } catch { return null; }
      if (!/^https?:/i.test(u)) return null;
      if (!seen.has(u)) { seen.set(u, res.length); res.push(u); }
      return `__csdkeep_${seen.get(u)}__`;
    };
    const cssFix = t => String(t)
      .replace(/url\(\s*(['"]?)([^'")]*)\1\s*\)/gi, (m, q, u) => { if (!u.trim() || /^(data:|blob:|#)/i.test(u.trim())) return m; const p = put(u); return p ? `url("${p}")` : m; })
      .replace(/@import\s+(['"])([^'"]+)\1/gi, (m, q, u) => { const p = put(u); return p ? `@import "${p}"` : m; });
    const abs = raw => { try { return new URL(raw, document.baseURI).href; } catch { return raw; } };
    const d = document;

    // what only the live page knows, before anything is taken out
    for (const sh of Array.from(d.styleSheets)) {
      const n = sh.ownerNode;
      if (!n || n.tagName !== "STYLE") continue;
      try {
        const live = Array.from(sh.cssRules, r => r.cssText).join("\n");
        if (live.length > (n.textContent || "").length + 20) n.textContent = live; // styles added from script
      } catch {}
    }
    let adopted = "";
    try { adopted = Array.from(d.adoptedStyleSheets || [], s => Array.from(s.cssRules, r => r.cssText).join("\n")).join("\n"); } catch {}
    for (const c of Array.from(d.querySelectorAll("canvas"))) {
      try { const img = d.createElement("img"); img.src = c.toDataURL(); img.width = c.width; img.height = c.height; img.style.cssText = c.style.cssText; img.className = c.className; c.replaceWith(img); } catch { c.remove(); }
    }
    for (const i of Array.from(d.querySelectorAll("img"))) {
      const s = i.currentSrc || i.getAttribute("src") || i.dataset.src || i.dataset.lazySrc || i.dataset.original || "";
      if (s && !/^data:/i.test(s)) { const p = put(s); if (p) i.setAttribute("src", p); }
      for (const a of ["srcset", "sizes", "loading", "decoding", "data-src", "data-srcset", "data-lazy-src"]) i.removeAttribute(a);
    }
    for (const v of Array.from(d.querySelectorAll("video"))) {
      const poster = v.getAttribute("poster");
      if (poster) { const img = d.createElement("img"); img.src = put(poster) || ""; img.style.cssText = v.style.cssText; img.className = v.className; img.style.maxWidth = "100%"; v.replaceWith(img); } else v.remove();
    }

    // what doesn't belong in a kept copy: scripts, frames, other pages' content, what would load more
    d.querySelectorAll("script, noscript, iframe, frame, frameset, object, embed, applet, audio, source, track, portal, template, base, meta[http-equiv], link:not([rel~='stylesheet']):not([rel~='icon'])").forEach(e => e.remove());
    d.querySelectorAll("picture").forEach(p => { const img = p.querySelector("img"); if (img) p.replaceWith(img); });
    for (const l of Array.from(d.querySelectorAll("link"))) { const p = put(l.getAttribute("href") || ""); if (p) { l.setAttribute("href", p); l.removeAttribute("integrity"); l.removeAttribute("crossorigin"); } else l.remove(); }
    d.querySelectorAll("style").forEach(s => { s.textContent = cssFix(s.textContent); });
    for (const e of Array.from(d.querySelectorAll("*"))) {
      for (const a of Array.from(e.attributes)) {
        const n = a.name.toLowerCase();
        if (n.startsWith("on") || n === "nonce" || n === "integrity") { e.removeAttribute(a.name); continue; }
        if (n === "style" && /url\(/i.test(a.value)) e.setAttribute("style", cssFix(a.value));
        if ((n === "href" || n === "src" || n === "action" || n === "formaction" || n === "xlink:href") && /^\s*javascript:/i.test(a.value)) e.removeAttribute(a.name);
      }
      if (e.tagName === "A" && e.getAttribute("href")) { const h = e.getAttribute("href"); if (!h.startsWith("#")) e.setAttribute("href", abs(h)); e.setAttribute("rel", "noopener"); }
      if (e.tagName === "FORM") e.removeAttribute("action");
      if (e.tagName === "INPUT" && e.type === "password") e.removeAttribute("value");
      else if (e.tagName === "INPUT" && e.type !== "hidden") e.setAttribute("value", e.value);
      if (e.tagName === "INPUT" && e.type === "hidden") e.remove();
      if (/^(IMAGE|USE)$/i.test(e.tagName)) for (const a of ["href", "xlink:href"]) { const v = e.getAttribute(a); if (v && !v.startsWith("#")) { const p = put(v); if (p) e.setAttribute(a, p); } }
    }
    if (adopted) { const s = d.createElement("style"); s.textContent = cssFix(adopted); d.head.appendChild(s); }
    d.querySelectorAll("meta[charset]").forEach(m => m.remove());
    const cs = d.createElement("meta"); cs.setAttribute("charset", "utf-8"); d.head.prepend(cs);
    // a page shown only once its scripts ran (hidden until "loaded", say) is shown as it was on screen
    for (const el of [d.documentElement, d.body]) if (el) { el.style.removeProperty("visibility"); el.style.removeProperty("opacity"); }

    return { ok: true, url: location.href, title: d.title || "", html: "<!doctype html>\n" + d.documentElement.outerHTML, res };
  } catch (e) {
    return { ok: false, error: String(e && e.message || e) };
  }
})()
