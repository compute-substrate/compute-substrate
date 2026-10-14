"""Extract every reference from the openai/math manuscripts (BibTeX and \\bibitem),
and run the checks that need no network:

  - arXiv identifiers that are malformed, or dated after the manuscript;
  - cited years later than the manuscript's own year;
  - malformed DOIs;
  - \\cite keys used in the text with no matching bibliography entry.

Usage: python3 refs_extract.py <preprints dir> <out.json>
"""
import os, re, sys, json, glob, datetime

MONTHS = {m: i for i, m in enumerate(['January', 'February', 'March', 'April', 'May', 'June', 'July',
                                      'August', 'September', 'October', 'November', 'December'], 1)}


def paper_date(name):
    m = re.search(r'-(January|February|March|April|May|June|July|August|September|October|November|December)-(\d{1,2})-(\d{4})$', name)
    return datetime.date(int(m.group(3)), MONTHS[m.group(1)], int(m.group(2))) if m else None


def bib_entries(text):
    """Brace-aware BibTeX reader: returns [{type, key, fields}]."""
    out, i = [], 0
    while True:
        m = re.compile(r'@(\w+)\s*\{', re.S).search(text, i)
        if not m:
            return out
        typ = m.group(1).lower()
        j, depth = m.end(), 1
        while j < len(text) and depth:
            depth += {'{': 1, '}': -1}.get(text[j], 0)
            j += 1
        body = text[m.end():j - 1]
        i = j
        if typ in ('comment', 'preamble', 'string'):
            continue
        key, _, rest = body.partition(',')
        fields, k = {}, 0
        while k < len(rest):
            fm = re.compile(r'\s*([\w-]+)\s*=\s*', re.S).match(rest, k)
            if not fm:
                k += 1
                continue
            name, k = fm.group(1).lower(), fm.end()
            if k < len(rest) and rest[k] in '{"':
                close = '}' if rest[k] == '{' else '"'
                d, s = 0, k
                while k < len(rest):
                    c = rest[k]
                    if c == '{': d += 1
                    elif c == '}': d -= 1
                    if (close == '}' and d == 0 and c == '}') or (close == '"' and c == '"' and k > s and d == 0):
                        break
                    k += 1
                val = rest[s + 1:k]
                k += 1
            else:
                vm = re.compile(r'[^,]*').match(rest, k)
                val, k = vm.group(0), vm.end()
            fields[name] = re.sub(r'\s+', ' ', val).strip()
        out.append({'type': typ, 'key': key.strip(), 'fields': fields})


def bibitems(text):
    out = []
    for m in re.finditer(r'\\bibitem(?:\[[^\]]*\])?\{([^}]*)\}(.*?)(?=\\bibitem|\\end\{thebibliography\})', text, re.S):
        out.append({'type': 'bibitem', 'key': m.group(1).strip(), 'fields': {'raw': re.sub(r'\s+', ' ', m.group(2)).strip()}})
    return out


ARX_NEW = re.compile(r'(?<![\d.])(\d{2})(\d{2})\.(\d{4,5})(v\d+)?(?![\d])')
ARX_OLD = re.compile(r'\b((?:math|hep-th|hep-ph|gr-qc|cond-mat|quant-ph|math-ph|nlin|physics|cs|q-alg|alg-geom|dg-ga|funct-an)(?:\.[A-Z]{2})?)/(\d{2})(\d{2})(\d{3})\b')
DOI = re.compile(r'\b10\.\d{4,9}/[^\s,}]+')


def arxiv_checks(blob, pdate):
    found, issues = [], []
    hint = re.search(r'arxiv|eprint|preprint', blob, re.I)
    for m in ARX_NEW.finditer(blob):
        yy, mm, seq = int(m.group(1)), int(m.group(2)), m.group(3)
        ident = m.group(0)
        if not hint and not re.search(r'arxiv\.org', blob, re.I):
            continue
        found.append(ident)
        if not 1 <= mm <= 12:
            issues.append(f'arXiv {ident}: month {mm:02d} does not exist')
            continue
        if yy < 7 or (yy == 7 and mm < 4):
            issues.append(f'arXiv {ident}: new-style identifiers began in April 2007')
        if (yy, mm) <= (14, 12) and len(seq) != 4:
            issues.append(f'arXiv {ident}: identifiers before 2015 have four digits after the dot')
        if (yy, mm) >= (15, 1) and len(seq) != 5:
            issues.append(f'arXiv {ident}: identifiers from 2015 on have five digits after the dot')
        if pdate and datetime.date(2000 + yy, mm, 1) > pdate:
            issues.append(f'arXiv {ident}: dated {2000 + yy}-{mm:02d}, after this manuscript ({pdate})')
    for m in ARX_OLD.finditer(blob):
        yy, mm = int(m.group(2)), int(m.group(3))
        found.append(m.group(0))
        year = 1900 + yy if yy >= 91 else 2000 + yy
        if not 1 <= mm <= 12:
            issues.append(f'arXiv {m.group(0)}: month {mm:02d} does not exist')
        elif (year, mm) > (2007, 3):
            issues.append(f'arXiv {m.group(0)}: old-style identifiers ended in March 2007')
    return found, issues


def main(root, outp):
    report = []
    for p in sorted(os.listdir(root)):
        d = os.path.join(root, p)
        if not os.path.isdir(d):
            continue
        pdate = paper_date(p)
        texs = glob.glob(f'{d}/build/**/*.tex', recursive=True)
        bibs = glob.glob(f'{d}/build/**/*.bib', recursive=True)
        entries = []
        for b in bibs:
            for e in bib_entries(open(b, encoding='utf-8', errors='replace').read()):
                e['file'] = os.path.relpath(b, d)
                entries.append(e)
        tex_all = ''
        for t in texs:
            s = open(t, encoding='utf-8', errors='replace').read()
            tex_all += '\n' + s
            for e in bibitems(s):
                e['file'] = os.path.relpath(t, d)
                entries.append(e)
        # keys cited in the text (comments stripped)
        body = re.sub(r'(?<!\\)%.*', '', tex_all)
        cited = set()
        for m in re.finditer(r'\\(?:no)?cite[a-zA-Z]*\*?(?:\[[^\]]*\]){0,2}\{([^}]*)\}', body):
            for k in m.group(1).split(','):
                k = k.strip()
                if k and k != '*':
                    cited.add(k)
        keys = {e['key'] for e in entries}
        refs = []
        for e in entries:
            f = e['fields']
            blob = ' '.join(f.values())
            arx, issues = arxiv_checks(blob, pdate)
            dois = DOI.findall(blob)
            for doi in dois:
                if re.search(r'[\\{}]', doi) or doi.endswith('.'):
                    issues.append(f'DOI {doi}: malformed')
            yr = None
            ym = re.search(r'\b(1[5-9]\d\d|20\d\d)\b', f.get('year', '') or f.get('date', '') or '')
            if not ym and e['type'] == 'bibitem':
                ys = re.findall(r'\b(1[5-9]\d\d|20\d\d)\b', f.get('raw', ''))
                ym = None
                yr = max(map(int, ys)) if ys else None
            elif ym:
                yr = int(ym.group(1))
            if yr and pdate and yr > pdate.year:
                issues.append(f'year {yr}: later than this manuscript ({pdate.year})')
            refs.append({'key': e['key'], 'type': e['type'], 'file': e['file'],
                         'title': f.get('title', ''), 'author': f.get('author', ''), 'year': yr,
                         'journal': f.get('journal', '') or f.get('booktitle', ''),
                         'doi': dois[0] if dois else '', 'arxiv': arx[0] if arx else '',
                         'raw': f.get('raw', ''), 'cited': e['key'] in cited, 'issues': issues})
        missing = sorted(k for k in cited if k not in keys)
        report.append({'paper': p, 'date': str(pdate) if pdate else None,
                       'n_refs': len(refs), 'refs': refs, 'missing_keys': missing})
    json.dump(report, open(outp, 'w'), indent=1)


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
