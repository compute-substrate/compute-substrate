"""Comment- and string-aware scan of Lean 4 sources for proof gaps.
Reports, per file: `sorry`, `admit` used as a tactic/term, new `axiom` declarations,
and `native_decide` (trusts the compiler, not the kernel)."""
import os, re, sys, json
def strip(src):
    out, i, n, depth = [], 0, len(src), 0
    while i < n:
        if depth == 0 and src.startswith('--', i):
            j = src.find('\n', i); i = n if j < 0 else j; continue
        if src.startswith('/-', i): depth += 1; i += 2; continue
        if depth and src.startswith('-/', i): depth -= 1; i += 2; continue
        if depth: 
            if src[i] == '\n': out.append('\n')
            i += 1; continue
        if src[i] == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == '\\' else 1
            out.append('""'); i = j + 1; continue
        out.append(src[i]); i += 1
    return ''.join(out)
PAT = {
  'sorry': re.compile(r'(?<![\w.\'])sorry(?![\w\'])'),
  'admit': re.compile(r'(?<![\w.\'])admit(?![\w\'])'),
  'axiom': re.compile(r'^\s*(?:@\[[^\]]*\]\s*)?(?:private\s+|protected\s+|noncomputable\s+|unsafe\s+)*axiom\s+([^\s:(]+)', re.M),
  'native_decide': re.compile(r'(?<![\w.\'])native_decide(?![\w\'])'),
}
if __name__ == '__main__':
    root = sys.argv[1]; res = {}
    for dp, _, fs in os.walk(root):
        for f in fs:
            if not f.endswith('.lean'): continue
            p = os.path.join(dp, f); s = strip(open(p, encoding='utf-8', errors='replace').read())
            hit = {}
            for k, rx in PAT.items():
                ms = list(rx.finditer(s))
                if ms: hit[k] = [(s.count('\n', 0, m.start()) + 1, m.group(1) if k == 'axiom' else k) for m in ms]
            if hit: res[os.path.relpath(p, root)] = hit
    json.dump(res, sys.stdout, indent=1)
