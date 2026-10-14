#!/usr/bin/env python3
"""Recheck the references the first pass could not settle, slowly and with errors kept
separate from 'not found'.  Standard library only.

    python3 recheck.py recheck_input.json recheck_results.json
"""
import json, re, sys, time, urllib.request, urllib.parse, urllib.error
UA = 'compute-substrate-anchors reference audit (python-urllib)'

def get(url):
    for k in range(5):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': UA}), timeout=30) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504):
                time.sleep(5 * (k + 1)); continue
            return e.code, b''
        except Exception:
            time.sleep(5 * (k + 1))
    return None, b''

def clean(doi):
    doi = urllib.parse.unquote(doi.replace('\\_', '_').replace('\\%', '%'))
    doi = re.sub(r'(\.pdf|[;.,])$', '', doi)
    return doi

out = []
items = json.load(open(sys.argv[1]))
for n, it in enumerate(items, 1):
    res = dict(it)
    if it['doi']:
        doi = clean(it['doi']); res['doi_cleaned'] = doi
        st, body = get('https://api.crossref.org/works/' + urllib.parse.quote(doi, safe='/'))
        res['crossref'] = st
        if st == 200:
            res['found_title'] = (json.loads(body)['message'].get('title') or [''])[0]
        time.sleep(1)
        st, body = get('https://doi.org/api/handles/' + urllib.parse.quote(doi, safe='/'))
        res['doi_org'] = st
        if st == 200:
            urls = [v['data']['value'] for v in json.loads(body).get('values', []) if v.get('type') == 'URL']
            res['resolves_to'] = urls[:1]
        res['verdict'] = ('exists' if 200 in (res['crossref'], res['doi_org'])
                          else 'does not exist' if res['crossref'] == 404 and res['doi_org'] == 404
                          else 'could not check')
    else:
        q = urllib.parse.urlencode({'query.bibliographic': it['title'][:300], 'rows': 1})
        st, body = get('https://api.crossref.org/works?' + q)
        res['crossref'] = st
        if st == 200:
            items2 = json.loads(body)['message'].get('items', [])
            if items2:
                res['found_title'] = (items2[0].get('title') or [''])[0]; res['found_doi'] = items2[0].get('DOI')
        res['verdict'] = 'searched'
    out.append(res)
    print(f"{n}/{len(items)} {it['key']}: {res['verdict']}", flush=True)
    time.sleep(1)
json.dump(out, open(sys.argv[2], 'w'), indent=1)
