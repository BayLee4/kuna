#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
from support import ROOT, cli as default_cli, output, tool, require_provider_body
import subprocess
import traceback
from whole_calls import Machine,rel

p=argparse.ArgumentParser();p.add_argument('--cli',type=Path);p.add_argument('--out',type=Path);p.add_argument('--scenario',choices=('both','clobbered','restored'),default='both');a=p.parse_args()
a.cli = (a.cli or default_cli()).resolve(); a.out = (a.out or output("preserved_register_effect")/"run").resolve()
a.out.mkdir(parents=True,exist_ok=False)
report={'cli_sha256':hashlib.sha256(a.cli.read_bytes()).hexdigest(),'scenarios':[],'completed':False}
for restore in ((False,True) if a.scenario=='both' else (a.scenario=='restored',)):
 name='restored' if restore else 'clobbered';out=a.out/name;out.mkdir()
 row={'name':name,'commands':[],'completed':False};report['scenarios'].append(row)
 try:
  dispatch=bytes.fromhex('488d35f9010000bf55000000')+rel(0xe8,0x100c,0x1100)+bytes([0xc3])
  target=bytes.fromhex('53bb07000000b8030000005bc3' if restore else 'bb07000000b803000000c3')
  entries=[('dispatch',0x1000,dispatch,'int dispatch(void)'),
           ('caller',0x1100,bytes.fromhex('53bb2a000000ffd689d85bc3'),'int caller(unsigned char value,Callback callback)'),
           ('target',0x1200,target,'int target(unsigned char value)')]
  image=bytearray(0x220)
  for _,pc,code,_ in entries:image[pc-0x1000:pc-0x1000+len(code)]=code
  binary=out/'preserved_register';binary.write_bytes(image)
  machine=Machine(bytes(image),entries)
  try:
   actual=machine.call(0x1000);want=42 if restore else 7
   assert actual==want,(name,actual,want)
   row['original_machine']=actual
  finally:machine.close()
  common=['--raw-image','--target','x86:LE:64:default:gcc','--base','0x1000','--sleighpath',ROOT/'specs','--assert-strict','--assert','typedef typedef int (*Callback)(unsigned char);']
  for fname,pc,code,prototype in entries:
   common+=['--addr',hex(pc),'--define-function',f'{pc:#x}-{pc+len(code):#x}={fname}','--assert','prototype '+fname+' '+prototype]
  def run(command):
   r=subprocess.run(list(map(str,command)),cwd='/tmp',capture_output=True,text=True,timeout=240)
   record={'command':list(map(str,command)),'status':r.returncode,'stdout':r.stdout,'stderr':r.stderr};row['commands'].append(record);return record
  meta=run([a.cli,'decompile-all',binary,'--json',*common]);assert meta['status']==0,meta
  functions=json.loads(meta['stdout'])['functions'];assert len(functions)==len(entries) and {f['name']for f in functions}=={entry[0]for entry in entries} and all(f.get('error') is None and f.get('code') for f in functions),functions
  project=out/'project';export=run([a.cli,'decompile-project',binary,'-o',project,*common])
  assert export['status']==0,export
  for provider,_,_,_ in entries:require_provider_body(project/'preserved_register.c',provider)
  if not restore:
   row['executable_extension_contract']='EX12/EXT03 conditional clobbered-register C observation'
  driver=out/'consumer.c';driver.write_text('#include "preserved_register.h"\n#include <stdio.h>\nint main(void){int got=dispatch();if(got!='+str(want)+'){fprintf(stderr,"got=%d expected='+str(want)+'\\n",got);return 1;}return 0;}\n')
  failures=[]
  for opt in ('-O0','-O2'):
   try:
    exe=out/('consumer'+opt)
    build=run([tool('cc'),'-std=c11','-Wall','-Wextra','-Werror=uninitialized','-Werror=incompatible-pointer-types','-Werror=implicit-function-declaration',opt,'-I',project,project/'preserved_register.c',driver,'-o',exe]);assert build['status']==0,build
    executed=run([exe]);assert executed['status']==0,executed
   except Exception:
    failures.append({'optimization':opt,'failure':traceback.format_exc()})
  if restore:
   assert not failures,failures
  elif failures:
   row['executable_extension_failures']=failures
  row['unchanged_c_executed']=not failures
  row['outcome']=('unchanged emitted C preserved observed register behavior'if not failures else
                  'ordinary selected bodies retained; conditional original C consumer failed')
  row['completed']=True
 except BaseException:
  row['failure']=traceback.format_exc()
report['completed']=all(row['completed']for row in report['scenarios'])
(a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if not report['completed']:raise SystemExit(1)
