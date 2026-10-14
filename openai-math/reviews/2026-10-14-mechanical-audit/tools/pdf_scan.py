"""Scan each manuscript's published PDF for unresolved LaTeX citations ([?]) and
broken cross-references (??), with the page and surrounding text of every hit."""
import os, re, sys, json, subprocess, glob
root, outp = sys.argv[1], sys.argv[2]
CIT = re.compile(r'\[(?:[^\[\]]{0,40},\s*)?\?(?:\s*,[^\[\]]{0,40})?\]')
REF = re.compile(r'(?<![?\w])\?\?(?![?\w])')
res = []
for p in sorted(os.listdir(root)):
    pdfs = [f for f in glob.glob(f'{root}/{p}/*.pdf') if os.path.basename(f) in ('paper.pdf', 'article.pdf')] or glob.glob(f'{root}/{p}/*.pdf')
    if not pdfs: res.append({'paper': p, 'pdf': None}); continue
    pdf = pdfs[0]
    txt = subprocess.run(['pdftotext', '-layout', pdf, '-'], capture_output=True, text=True, errors='replace').stdout
    pages = txt.split('\f'); hits = []
    for pi, pg in enumerate(pages, 1):
        for kind, rx in (('unresolved citation', CIT), ('broken reference', REF)):
            for m in rx.finditer(pg):
                s = max(0, m.start() - 70); ctx = re.sub(r'\s+', ' ', pg[s:m.end() + 70])
                hits.append({'kind': kind, 'page': pi, 'match': m.group(0), 'context': ctx})
    res.append({'paper': p, 'pdf': os.path.basename(pdf), 'pages': len(pages) - (1 if pages and not pages[-1].strip() else 0), 'hits': hits})
json.dump(res, open(outp, 'w'), indent=1)
