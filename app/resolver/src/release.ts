// The newest Doorway, from the project's GitHub releases: the highest app-v version that has the
// apps (GitHub lists releases by date, not version, and the node's own releases are mixed in).
export const REPO = "compute-substrate/compute-substrate";
export type Release = { tag: string; version: string; mac: string; win: string; doorSh: string | null };

export const versionOf = (tag: string) => tag.replace(/^app-v/, "");
// a.b.c against a.b.c, numerically: 0.2.11 is newer than 0.2.9
export function newer(a: string, b: string) {
  const x = a.split(".").map(Number), y = b.split(".").map(Number);
  for (let i = 0; i < Math.max(x.length, y.length); i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) > (y[i] ?? 0);
  return false;
}

let asked: Promise<Release | null> | null = null;
export function newestDoorway(): Promise<Release | null> {
  asked ??= (async () => {
    try {
      const rs = await (await fetch(`https://api.github.com/repos/${REPO}/releases?per_page=60`, { signal: AbortSignal.timeout(8000) })).json();
      let best: any = null;
      for (const r of rs as any[]) {
        if (!/^app-v\d+(\.\d+)*$/.test(r.tag_name) || r.draft || r.prerelease || !r.assets?.some((a: any) => a.name === "Doorway-macOS.dmg")) continue;
        if (!best || newer(versionOf(r.tag_name), versionOf(best.tag_name))) best = r;
      }
      if (!best) return null;
      const base = `https://github.com/${REPO}/releases/download/${best.tag_name}`;
      return { tag: best.tag_name, version: versionOf(best.tag_name), mac: `${base}/Doorway-macOS.dmg`, win: `${base}/Doorway-Windows-setup.exe`,
        doorSh: best.assets.some((a: any) => a.name === "door.sh") ? `${base}/door.sh` : null };
    } catch { asked = null; return null; }
  })();
  return asked;
}
