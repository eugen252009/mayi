#!/usr/bin/env python3
"""Standard-library GitHub Markdown/navigation audit; no application imports or writes.
Run from any directory: python3 docs/development/check_documentation.py --json result.json
Historical bodies are verified at explicit original commit/path, not reinterpreted
relative to archive destinations. Requires full Git history, not a website/service.
"""
from pathlib import Path
import argparse,json,os,re,subprocess,urllib.parse
B='03318f689fb70678366de06c3bfa038c00a71567'
OLD='3b6b6127c6af682e3f7894dd1b98bac31a04a2e3'
SECTIONS=['Getting Started','Architecture','Security Model','Authentication and PAM','Requests and Capabilities','Broker Restart and Epochs','CLI and Approval Interface','Journald and History','Live Status and Preflight','Building and Packaging','Security Qualification','Why Does This Exist?','Component Map','Design Decisions','Historical Research','Known Limitations','Documentation Authority']

def git(root,*args):return subprocess.run(['git','-C',str(root),*args],capture_output=True)
def original(name):
 rules=[('docs/historical/baseline-3b6/',OLD,''),('docs/historical/navigation-03318f6/',B,''),('docs/historical/releases/',B,''),('docs/historical/experiments/',B,'docs/history/'),('docs/historical/audits/',B,'docs/historical/older-audits/')]
 for prefix,commit,base in rules:
  if name.startswith(prefix) and name!=prefix+'INDEX.md':
   rel=name[len(prefix):]
   if prefix.endswith('baseline-3b6/') and rel=='AGENTS.md.txt':rel='AGENTS.md'
   return commit,base+rel
 return None

def slug(s):
 s=re.sub(r'<[^>]*>','',s.lower());return re.sub(r'[^\w\- ]','',s).replace(' ','-')
def anchors(text):
 found=set();counts={}
 for line in text.splitlines():
  if not re.match(r'^#{1,6}\s',line):continue
  s=slug(re.sub(r'^#+\s*','',line).strip());n=counts.get(s,0);counts[s]=n+1;found.add(s+('-'+str(n) if n else ''))
 found.update(re.findall(r'<a\s+(?:id|name)=[\"\']([^\"\']+)',text));return found

def links(text):
 prose=re.sub(r'```.*?```','',text,flags=re.S);prose=re.sub(r'`[^`\n]+`','',prose)
 return re.findall(r'!?\[[^\]\n]*\]\(([^)\n]+)\)',prose)+re.findall(r'^\[[^\]]+\]:\s*(\S+)',prose,re.M)

def audit(root):
 root=Path(root).resolve();errors=[];recovered=[];count=0;snapshots=0
 cp=git(root,'ls-files','--cached','--others','--exclude-standard','-z')
 if cp.returncode:raise ValueError('requires a Git checkout with historical objects')
 files=sorted({x for x in cp.stdout.decode().split('\0') if x and (root/x).is_file()})
 md=[x for x in files if x.endswith('.md')]
 root_md=sorted(p.name for p in root.iterdir() if p.suffix.lower()=='.md')
 if root_md!=['AGENTS.md','PROJECT_STATUS.md','README.md'] or any(p.is_symlink() for p in root.iterdir() if p.suffix.lower()=='.md'):
  errors.append({'error':'root Markdown must be exactly three regular entrypoints','actual':root_md})
 # Check archived manpage/AGENTS bytes too, not only Markdown.
 for name in files:
  spec=original(name)
  if not spec:continue
  commit,path=spec;r=git(root,'show',commit+':'+path)
  if r.returncode or r.stdout!=(root/name).read_bytes():errors.append({'file':name,'error':'historical snapshot differs from original commit/path'})
  snapshots+=1
 for name in md:
  text=(root/name).read_text();spec=original(name)
  for raw in links(text):
   raw=raw.strip().split(' "')[0].strip('<>');u=urllib.parse.urlsplit(raw)
   if u.scheme or raw.startswith('//'):continue
   count+=1;part=urllib.parse.unquote(u.path)
   base=Path(spec[1]).parent if spec else Path(name).parent
   target=Path(os.path.normpath(str(base/part))) if part else Path(spec[1] if spec else name)
   if target.is_absolute() or '..' in target.parts:errors.append({'file':name,'link':raw,'error':'path escapes repository'});continue
   body=None;problem=None
   if spec:
    r=git(root,'show',spec[0]+':'+target.as_posix())
    if r.returncode==0:body=r.stdout.decode(errors='replace')
    else:
     # These audit notes were absent in the original3b6 tree; preserved later.
     recovered_path=root/'docs/historical/audits'/target.name
     if target.name in ['AUDIT_REPORT_0.4.1-3.md','AUDIT_REPORT_0.4.1-4.md'] and recovered_path.is_file():
      body=recovered_path.read_text();recovered.append({'file':name,'link':raw,'current_preserved_target':str(recovered_path.relative_to(root))})
     else:problem='missing historical original-base target'
   else:
    dest=root/target
    if not dest.exists():problem='missing current target'
    elif dest.is_file():body=dest.read_text(errors='replace')
   if not problem and u.fragment and body is not None and urllib.parse.unquote(u.fragment) not in anchors(body):problem='missing heading anchor'
   if problem:errors.append({'file':name,'link':raw,'error':problem})
 index=(root/'docs/INDEX.md').read_text();decisions=(root/'docs/decisions/INDEX.md').read_text()
 for heading in SECTIONS:
  if '## '+heading not in index:errors.append({'error':'missing index section','heading':heading})
 ids=re.findall(r'^## (D\d\d) ',decisions,re.M)
 if not ids or ids!=['D%02d'%i for i in range(1,len(ids)+1)]:errors.append({'error':'decision IDs must be unique and sequential from D01'})
 for section in re.split(r'^## (?=D\d\d )',decisions,flags=re.M)[1:]:
  ident=section[:3]
  if not links(section) or not any('/executor/' in x or '/mayi/' in x for x in links(section)):errors.append({'error':'rationale lacks source/supporting reference','decision':ident})
  if '#'+slug(section.splitlines()[0]) not in index:errors.append({'error':'index does not link rationale','decision':ident})
 for source in ['executor/src/broker.rs','executor/src/pam_auth.rs','executor/src/approval_ui.rs','executor/src/audit.rs','executor/src/request_ids.rs','executor/src/broker_epoch.rs','executor/src/queue_snapshot.rs','mayi/cli.py','mayi/history.py','mayi/approval_status.py','executor/package/tpa.json','man/mayi.1']:
  if source not in index or not (root/source).is_file():errors.append({'error':'component map coverage','source':source})
 for name in ['README.md','AGENTS.md']:
  if 'docs/INDEX.md' not in (root/name).read_text():errors.append({'error':'entrypoint missing index link','file':name})
 for p in ['docs/security/SECURITY_MODEL.md','docs/security/LIMITATIONS.md']:
  if not (root/p).is_file():errors.append({'error':'canonical security owner missing','path':p})
 if 'DISCONNECTED / INCOMPLETE' not in (root/'docs/security/FILESYSTEM_EXECUTOR_STATUS.md').read_text():errors.append({'error':'filesystem qualification scope missing'})
 if '# Documentation moved' not in (root/'docs/SECURITY_MODEL.md').read_text():errors.append({'error':'former security URL is not a compatibility pointer'})
 return {'status':'PASS' if not errors else 'FAIL','markdown_files':len(md),'links_checked':count,'historical_bodies_verified':snapshots,'rationales':len(ids),'component_sources':12,'index_sections':len(SECTIONS),'historical_recovered_links':recovered,'errors':errors,'scope':'local targets, GitHub-style heading anchors, pinned historical bodies, explicit index/rationale/source coverage; external URL availability and prose correctness require review'}

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[2]);p.add_argument('--json',type=Path);a=p.parse_args()
 result=audit(a.root);text=json.dumps(result,indent=2)+'\n'
 if a.json:a.json.write_text(text)
 print(text,end='');return 0 if result['status']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
