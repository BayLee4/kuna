#!/usr/bin/env python3
"""Real finite Big24 provider closure: omission refusal and unchanged project C."""
import argparse,hashlib,json,subprocess,traceback
from pathlib import Path
from whole_calls_workers import elf_symbols
p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--cli',type=Path,required=True);p.add_argument('--sha256',required=True);a=p.parse_args();a.binary=a.binary.resolve();a.out=a.out.resolve();a.cli=a.cli.resolve();a.out.mkdir(parents=True,exist_ok=False);r={'completed':False,'binary_sha256':hashlib.sha256(a.binary.read_bytes()).hexdigest(),'cli_sha256':hashlib.sha256(a.cli.read_bytes()).hexdigest(),'cases':[],'native_lifecycle_limit':'Original machine/raw BLR and provider ownership are authenticated separately. Actual native SSA finite-target/MULTIEQUAL operation identities must come from the Main engine diagnostic; no C-text claim substitutes.'};assert r['cli_sha256']==a.sha256;symbols=elf_symbols(a.binary)
declarations=['typedef typedef struct Big24 { unsigned long long a; unsigned long long b; unsigned long long c; } Big24;','prototype make_big_a Big24 make_big_a(int tag)','prototype make_big_b Big24 make_big_b(int tag)','prototype finite_static unsigned long long finite_static(int tag)','prototype finite_phi unsigned long long finite_phi(int tag,int which)'];assertions=['--assert-strict']
for declaration in declarations:assertions+=['--assert',declaration]
for root,providers,omitted in [('finite_static',['make_big_a'],'make_big_a'),('finite_phi',['make_big_a','make_big_b'],'make_big_b')]:
 directory=a.out/root;directory.mkdir();row={'root':root,'completed':False,'commands':[]};r['cases'].append(row)
 def invoke(command):
  command=list(map(str,command));q=subprocess.run(command,cwd='/tmp',capture_output=True,text=True,timeout=240);result={'command':command,'status':q.returncode,'stdout':q.stdout,'stderr':q.stderr};row['commands'].append(result);return result
 try:
  for missing in [True,False]:
   names=[root,*[name for name in providers if not missing or name!=omitted]];label='omitted'if missing else'full';common=['--functions',','.join(names),'--language','c','--option','structdefs','on',*assertions]
   result=invoke([a.cli,'decompile-all',a.binary,'--json',*common]);assert result['status']==0,result;metadata=json.loads(result['stdout']);(directory/(label+'-metadata.json')).write_text(json.dumps(metadata,indent=2)+'\n')
   functions=metadata['functions'];assert len(functions)==len(names)
   assert all(f.get('error')is None and f.get('code')and f.get('callable_export_error')is None for f in functions),metadata
   artifacts=[artifact for f in functions for artifact in f.get('callable_artifacts',[])]
   required={artifact['key']for artifact in artifacts if artifact.get('required')};assert required,metadata
   owners={artifact['key']for artifact in artifacts if artifact.get('definition')is not None}
   project=directory/label;result=invoke([a.cli,'decompile-project',a.binary,'-o',project,*common])
   if missing:
    assert result['status']!=0 and required-owners,{'export':result,'required':sorted(required),'owners':sorted(owners)}
    row['omitted_provider']={'actual_function':omitted,'address':symbols[omitted],'unowned_required_keys':sorted(required-owners),'export_refused':True};continue
   assert result['status']==0,result
   row['actual_provider_owners']={}
   for provider in providers:
    owned=[artifact for f in functions if f['address']==symbols[provider]for artifact in f.get('callable_artifacts',[])if artifact['key']in required and artifact.get('definition')is not None]
    assert owned,{'provider':provider,'address':symbols[provider],'metadata':metadata}
    row['actual_provider_owners'][provider]={'address':symbols[provider],'receipts':owned}
   stem=a.binary.name;header=project/(stem+'.h');body=project/(stem+'.c');row['emitted_sha256']={path.name:hashlib.sha256(path.read_bytes()).hexdigest()for path in [header,body]}
   if root=='finite_static':
    checks='Big24 a=make_big_a(tag);if(a.a!=t||a.b!=7||a.c!=t+3)return 1;if(finite_static(tag)!=t+t+3)return 2;'
   else:
    checks='Big24 a=make_big_a(tag),b=make_big_b(tag);if(a.a!=t||a.b!=7||a.c!=t+3)return 1;if(b.a!=t+10||b.b!=11||b.c!=t+20)return 2;if(finite_phi(tag,0)!=t+t+3)return 3;if(finite_phi(tag,1)!=t+t+30)return 4;'
   driver=directory/'consumer.c';driver.write_text('#include "'+stem+'.h"\n#include <stddef.h>\n_Static_assert(sizeof(Big24)==24,"actual Big24 size");\n_Static_assert(offsetof(Big24,a)==0 && offsetof(Big24,b)==8 && offsetof(Big24,c)==16,"actual Big24 fields");\nint main(void){for(int tag=-20;tag<=20;tag++){unsigned long long t=(unsigned long long)(long long)tag;'+checks+'}return 0;}\n')
   for optimization in ['-O0','-O2']:
    binary=directory/('consumer'+optimization);result=invoke(['cc','-std=c11','-Wall','-Wextra','-Werror=uninitialized','-Werror=incompatible-pointer-types','-Werror=implicit-function-declaration',optimization,'-I',project,body,driver,'-o',binary]);assert result['status']==0,result;result=invoke([binary]);assert result['status']==0,result
   row['unchanged_C_passed']=True
  row['completed']=True
 except BaseException:row['failure']=traceback.format_exc()
 finally:(directory/'report.json').write_text(json.dumps(row,indent=2)+'\n');print(json.dumps({'root':root,'completed':row['completed'],'failure':row.get('failure')}),flush=True)
r['completed']=all(row['completed']for row in r['cases']);(a.out/'report.json').write_text(json.dumps(r,indent=2)+'\n')
if not r['completed']:raise SystemExit(1)
