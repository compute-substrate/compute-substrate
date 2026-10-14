import json,re,sys,html
sys.path.insert(0,'tools'); from ref_check import sim, norm
L=[json.loads(l) for l in open('ref_results.jsonl')]
R={r['paper']:r for r in json.load(open('refs.json'))}
def clean(t):
    t=re.sub(r'<mml:math.*?</mml:math>',' $ ',t or '',flags=re.S)
    t=re.sub(r'<[^>]+>',' ',t); return html.unescape(re.sub(r'\s+',' ',t)).strip()
def cited(ref):
    t=ref['title'] or ''
    t=re.sub(r'\\href\{[^}]*\}\{(.*)\}',r'\1',t)
    t=re.sub(r'\$[^$]*\$',' $ ',t)
    return t
out=[]
for d in L:
    ref=R[d['paper']]['refs'][d['i']]
    if d['status']!='found' or not ref['title']: continue
    ft=clean(d.get('found_title',''))
    if not ft: continue
    a=' '.join(w for w in norm(cited(ref)) if len(w)>1); b=' '.join(w for w in norm(ft) if len(w)>1)
    from difflib import SequenceMatcher
    s=1.0 if (a and b and (a in b or b in a)) else SequenceMatcher(None,a,b).ratio()
    # also word overlap
    A,B=set(a.split()),set(b.split()); ov=len(A&B)/max(1,min(len(A),len(B)))
    out.append((round(s,3),round(ov,2),d,ref,ft))
low=[o for o in out if o[0]<0.6 and o[1]<0.6]
print(len(out),'comparable;',len(low),'low after cleaning')
for s,ov,d,ref,ft in sorted(low,key=lambda o:o[0]):
    print(f"{s} {ov} | {d['source']} | {d['paper'][:45]} | {ref['key']} | {d['doi'] or d['arxiv']}\n   cited: {cited(ref)[:110]} ({ref['author'][:35]}, {ref['year']}; {ref['journal'][:30]})\n   found: {ft[:110]} ({d.get('found_year')})")
