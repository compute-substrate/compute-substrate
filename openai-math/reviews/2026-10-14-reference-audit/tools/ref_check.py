#!/usr/bin/env python3
"""Check that the works cited in the openai/math release exist and match how they are cited.

Standard library only. Resumable: results are appended to the output file one line per
reference, and a rerun skips references already checked.

    python3 ref_check.py refs.json ref_results.jsonl

For each reference:
  - DOI given      -> look it up at Crossref; record whether it resolves and the title it resolves to.
  - arXiv id given -> look it up at arXiv; record whether it exists and its title.
  - neither        -> search Crossref by the citation text; record the best match and its score.

It then compares the title it found with the title cited. Nothing here decides that a
reference is wrong: low similarity only marks a reference for a person to look at.
"""
import json, os, re, sys, time, unicodedata, urllib.request, urllib.parse, urllib.error
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from difflib import SequenceMatcher

UA = 'compute-substrate-anchors reference audit (python-urllib)'


def get(url, tries=4):
    for k in range(tries):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': UA})
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return 404, b''
            if e.code in (429, 500, 502, 503, 504):
                time.sleep(2 ** k * 2)
                continue
            return e.code, b''
        except Exception:
            time.sleep(2 ** k)
    return None, b''


def norm(s):
    s = re.sub(r'\\[a-zA-Z]+\*?', ' ', s or '')
    s = s.replace('{', '').replace('}', '').replace('$', '')
    s = unicodedata.normalize('NFKD', s)
    s = ''.join(c for c in s if not unicodedata.combining(c))
    return re.sub(r'[^a-z0-9 ]+', ' ', s.lower()).split()


def sim(a, b):
    a, b = ' '.join(norm(a)), ' '.join(norm(b))
    if not a or not b:
        return None
    if a in b or b in a:
        return 1.0
    return round(SequenceMatcher(None, a, b).ratio(), 3)


def cited_title(ref):
    if ref.get('title'):
        return ref['title']
    raw = ref.get('raw', '')
    m = re.search(r'\\emph\{(.+?)\}|\\textit\{(.+?)\}|``(.+?)\'\'', raw)
    return next(g for g in m.groups() if g) if m else raw


def crossref_doi(doi):
    doi = doi.replace('\\_', '_').replace('\\%', '%').rstrip('.')
    doi = urllib.parse.unquote(doi)
    st, body = get('https://api.crossref.org/works/' + urllib.parse.quote(doi, safe='/'))
    if st == 200:
        m = json.loads(body)['message']
        return {'status': 'found', 'found_title': (m.get('title') or [''])[0],
                'found_year': (m.get('issued', {}).get('date-parts') or [[None]])[0][0]}
    if st == 404:
        # some DOIs are registered with DataCite or mEDRA rather than Crossref
        st2, _ = get('https://doi.org/api/handles/' + urllib.parse.quote(doi, safe='/'))
        return {'status': 'resolves at doi.org, not in Crossref' if st2 == 200 else 'DOI not found'}
    return {'status': f'lookup failed ({st})'}


def crossref_search(text):
    q = urllib.parse.urlencode({'query.bibliographic': text[:300], 'rows': 1})
    st, body = get('https://api.crossref.org/works?' + q)
    if st != 200:
        return {'status': f'lookup failed ({st})'}
    items = json.loads(body)['message'].get('items', [])
    if not items:
        return {'status': 'no match'}
    it = items[0]
    return {'status': 'best match', 'found_title': (it.get('title') or [''])[0], 'found_doi': it.get('DOI'),
            'score': it.get('score')}


def arxiv_batch(ids):
    q = urllib.parse.urlencode({'id_list': ','.join(ids), 'max_results': len(ids)})
    st, body = get('https://export.arxiv.org/api/query?' + q)
    out = {}
    if st != 200:
        return {i: {'status': f'lookup failed ({st})'} for i in ids}
    ns = {'a': 'http://www.w3.org/2005/Atom'}
    root = ET.fromstring(body)
    for e in root.findall('a:entry', ns):
        idurl = e.findtext('a:id', '', ns)
        title = re.sub(r'\s+', ' ', e.findtext('a:title', '', ns)).strip()
        if title == 'Error':
            continue
        key = re.sub(r'v\d+$', '', idurl.split('/abs/')[-1])
        out[key] = {'status': 'found', 'found_title': title}
    return {i: out.get(re.sub(r'v\d+$', '', i), {'status': 'arXiv id not found'}) for i in ids}


def main(inp, outp):
    papers = json.load(open(inp))
    todo = []
    for p in papers:
        for k, r in enumerate(p['refs']):
            todo.append((p['paper'], k, r))
    done = set()
    if os.path.exists(outp):
        for line in open(outp):
            d = json.loads(line)
            done.add((d['paper'], d['i']))
    todo = [t for t in todo if (t[0], t[1]) not in done]
    print(f'{len(todo)} references to check ({len(done)} already done)', flush=True)
    out = open(outp, 'a')

    def emit(paper, i, ref, res):
        res.update({'paper': paper, 'i': i, 'key': ref['key'], 'doi': ref.get('doi', ''), 'arxiv': ref.get('arxiv', ''),
                    'cited_title': cited_title(ref)[:300]})
        if res.get('found_title'):
            res['similarity'] = sim(res['cited_title'], res['found_title'])
        out.write(json.dumps(res) + '\n')
        out.flush()

    # arXiv: batches of 50, one request every three seconds, as arXiv asks
    ax = [(p, i, r) for p, i, r in todo if r.get('arxiv') and not r.get('doi')]
    for b in range(0, len(ax), 50):
        chunk = ax[b:b + 50]
        res = arxiv_batch([r['arxiv'] for _, _, r in chunk])
        for p, i, r in chunk:
            emit(p, i, r, dict(res[r['arxiv']], source='arxiv'))
        print(f'arXiv {min(b + 50, len(ax))}/{len(ax)}', flush=True)
        time.sleep(3)

    # Crossref: DOIs, then searches for references with no identifier
    rest = [(p, i, r) for p, i, r in todo if not (r.get('arxiv') and not r.get('doi'))]

    def work(t):
        p, i, r = t
        if r.get('doi'):
            return t, dict(crossref_doi(r['doi']), source='crossref doi')
        text = ' '.join(x for x in (cited_title(r), r.get('author', ''), r.get('journal', ''), str(r.get('year') or '')) if x)
        return t, dict(crossref_search(text), source='crossref search')

    n = 0
    with ThreadPoolExecutor(max_workers=4) as ex:
        for (p, i, r), res in ex.map(work, rest):
            emit(p, i, r, res)
            n += 1
            if n % 250 == 0:
                print(f'Crossref {n}/{len(rest)}', flush=True)
    print('done', flush=True)


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
