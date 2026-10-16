#!/usr/bin/env python3
"""Finite Big24 provider omissions, return-control boundaries, and unchanged C."""
import argparse,hashlib,json,subprocess,traceback
from pathlib import Path
from support import require_provider_body, require_absent_provider_body
from whole_calls_workers import elf_symbols
p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--cli',type=Path,required=True);p.add_argument('--sha256',required=True);a=p.parse_args();a.binary=a.binary.resolve();a.out=a.out.resolve();a.cli=a.cli.resolve();a.out.mkdir(parents=True,exist_ok=False);r={'completed':False,'binary_sha256':hashlib.sha256(a.binary.read_bytes()).hexdigest(),'cli_sha256':hashlib.sha256(a.cli.read_bytes()).hexdigest(),'cases':[]};assert r['cli_sha256']==a.sha256;symbols=elf_symbols(a.binary)
declarations=['typedef typedef struct Big24 { unsigned long long a; unsigned long long b; unsigned long long c; } Big24;','prototype make_big_a Big24 make_big_a(int tag)','prototype make_big_b Big24 make_big_b(int tag)','prototype finite_static unsigned long long finite_static(int tag)','prototype finite_phi unsigned long long finite_phi(int tag,int which)'];assertions=['--assert-strict']
for declaration in declarations:assertions+=['--assert',declaration]
for root,providers,omitted in [('finite_static',['make_big_a'],'make_big_a'),('finite_phi',['make_big_a','make_big_b'],'make_big_b')]:
 directory=a.out/root;directory.mkdir();row={'root':root,'completed':False,'commands':[]};r['cases'].append(row)
 def invoke(command):
  command=list(map(str,command));q=subprocess.run(command,cwd='/tmp',capture_output=True,text=True,timeout=240);result={'command':command,'status':q.returncode,'stdout':q.stdout,'stderr':q.stderr};row['commands'].append(result);return result
 row['failures']=[]
 for missing in [True,False]:
  label='omitted'if missing else'full';stage='metadata'
  try:
   names=[root,*[name for name in providers if not missing or name!=omitted]];common=['--functions',','.join(names),'--language','c','--option','structdefs','on',*assertions]
   result=invoke([a.cli,'decompile-all',a.binary,'--json',*common]);assert result['status']==0,result;metadata=json.loads(result['stdout']);(directory/(label+'-metadata.json')).write_text(json.dumps(metadata,indent=2)+'\n')
   functions=metadata['functions'];assert len(functions)==len(names) and {f['name']for f in functions}==set(names),metadata
   assert all(f.get('error')is None and f.get('code')for f in functions),metadata
   stage='export'
   project=directory/label;result=invoke([a.cli,'decompile-project',a.binary,'-o',project,*common])
   if missing:
    stage='partial-selection'
    assert result['status']==0,result
    assert all(f['address']!=symbols[omitted]for f in functions),metadata
    for name in names:require_provider_body(project/(a.binary.name+'.c'),name)
    require_absent_provider_body(project/(a.binary.name+'.c'),omitted)
    row['omitted_provider']={'actual_function':omitted,'address':symbols[omitted],'selected_bodies':names,'project_status':result['status']};continue
   assert result['status']==0,result
   stage='providers'
   row['actual_provider_owners']={}
   require_provider_body(project/(a.binary.name+'.c'),root)
   for provider in providers:
    owner=next(f for f in functions if f['name']==provider);assert owner['address']==symbols[provider],owner
    require_provider_body(project/(a.binary.name+'.c'),provider)
    row['actual_provider_owners'][provider]={'address':owner['address']}
   stem=a.binary.name;header=project/(stem+'.h');body=project/(stem+'.c');row['emitted_sha256']={path.name:hashlib.sha256(path.read_bytes()).hexdigest()for path in [header,body]}
   if root=='finite_static':
    checks='Big24 a=make_big_a(tag);if(a.a!=t||a.b!=7||a.c!=t+3)return 1;if(finite_static(tag)!=t+t+3)return 2;'
   else:
    checks='Big24 a=make_big_a(tag),b=make_big_b(tag);if(a.a!=t||a.b!=7||a.c!=t+3)return 1;if(b.a!=t+10||b.b!=11||b.c!=t+20)return 2;if(finite_phi(tag,0)!=t+t+3)return 3;if(finite_phi(tag,1)!=t+t+30)return 4;'
   driver=directory/'consumer.c';driver.write_text('#include "'+stem+'.h"\n#include <stddef.h>\n_Static_assert(sizeof(Big24)==24,"actual Big24 size");\n_Static_assert(offsetof(Big24,a)==0 && offsetof(Big24,b)==8 && offsetof(Big24,c)==16,"actual Big24 fields");\nint main(void){for(int tag=-20;tag<=20;tag++){unsigned long long t=(unsigned long long)(long long)tag;'+checks+'}return 0;}\n')
   consumer_failures=[]
   for optimization in ['-O0','-O2']:
    try:
     stage='compile'+optimization
     binary=directory/('consumer'+optimization);result=invoke(['cc','-std=c11','-Wall','-Wextra','-Werror=uninitialized','-Werror=incompatible-pointer-types','-Werror=implicit-function-declaration',optimization,'-I',project,body,driver,'-o',binary]);assert result['status']==0,result
     stage='execute'+optimization
     result=invoke([binary]);assert result['status']==0,result
    except BaseException:
     failure={'phase':label,'stage':stage,'failure':traceback.format_exc()};consumer_failures.append(failure);row['failures'].append(failure)
   row['unchanged_C_passed']=not consumer_failures
  except BaseException:
   failure=traceback.format_exc();row['failures'].append({'phase':label,'stage':stage,'failure':failure});row.setdefault('failure',failure)
 row['completed']=not row['failures']
 (directory/'report.json').write_text(json.dumps(row,indent=2)+'\n');print(json.dumps({'root':root,'completed':row['completed'],'failures':row['failures']}),flush=True)
for root in ['wrong_return','mixed_return','observed_link','overwritten_link']:
 row={'root':root,'completed':False,'commands':[]};r['cases'].append(row)
 try:
  target=root+'_target';project=a.out/root
  common=['--functions',root+','+target,'--language','c','--option','structdefs','on',*assertions,'--assert','prototype '+root+' unsigned long long '+root+'(int tag)','--assert','prototype '+target+' Big24 '+target+'(int tag)']
  command=list(map(str,[a.cli,'decompile-all',a.binary,'--json',*common]))
  result=subprocess.run(command,cwd='/tmp',capture_output=True,text=True,timeout=240)
  row['commands'].append({'command':command,'status':result.returncode,'stderr':result.stderr})
  assert result.returncode==0,result.stderr
  metadata=json.loads(result.stdout);functions=metadata['functions']
  assert len(functions)==2 and {f['name']for f in functions}=={root,target},metadata
  (a.out/(root+'-metadata.json')).write_text(json.dumps(metadata,indent=2)+'\n')
  command=list(map(str,[a.cli,'decompile-project',a.binary,'-o',project,*common]))
  result=subprocess.run(command,cwd='/tmp',capture_output=True,text=True,timeout=240)
  observation={'command':command,'status':result.returncode,'stdout':result.stdout,'stderr':result.stderr}
  row['commands'].append(observation)
  assert result.returncode==0,observation
  for name in (root,target):require_provider_body(project/(a.binary.name+'.c'),name)
  row['completed']=True
 except BaseException:row['failure']=traceback.format_exc()
 print(json.dumps({'root':root,'completed':row['completed'],'failure':row.get('failure')}),flush=True)
r['completed']=all(row['completed']for row in r['cases']);(a.out/'report.json').write_text(json.dumps(r,indent=2)+'\n')
if not r['completed']:raise SystemExit(1)
