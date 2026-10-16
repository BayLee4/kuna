#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
from support import ROOT, cli as default_cli, output, tool, record_unrepresented_admission
import subprocess
import traceback
from whole_calls import Machine

parser=argparse.ArgumentParser()
parser.add_argument('--cli',type=Path)
parser.add_argument('--out',type=Path)
args=parser.parse_args()
args.cli = (args.cli or default_cli()).resolve(); args.out = (args.out or output("callback_effects")/"run").resolve()
args.out.mkdir(parents=True,exist_ok=False)
entries=[
  ('native_dispatch',0x1000,bytes.fromhex('488b35f9020000bf55000000b855000000e8ea000000c3'),'int native_dispatch(void)'),
  ('invoke',0x1100,bytes.fromhex('ffd6c3'),'int invoke(unsigned char value,Callback callback)'),
  ('native_target',0x1200,bytes.fromhex('c3'),'int native_target(unsigned char value)'),
 ]
image=bytearray(0x308)
for _,pc,code,_ in entries:image[pc-0x1000:pc-0x1000+len(code)]=code
image[0x300:0x308]=(0x1200).to_bytes(8,'little')
binary=args.out/'callback_effects';binary.write_bytes(image)
report={'cli_sha256':hashlib.sha256(args.cli.read_bytes()).hexdigest(),'commands':[],'completed':False}
def invoke(command):
 result=subprocess.run(list(map(str,command)),cwd='/tmp',capture_output=True,text=True,timeout=240)
 row={'command':list(map(str,command)),'status':result.returncode,'stdout':result.stdout,'stderr':result.stderr}
 report['commands'].append(row)
 return row
try:
 machine=Machine(bytes(image),entries)
 try:
  actual=machine.call(0x1000)
  assert actual==85,actual
 finally:machine.close()
 report['machine']={'loaded_native_observed_preserved_rax':85}
 common=['--raw-image','--target','x86:LE:64:default:gcc','--base','0x1000',
         '--sleighpath',ROOT/'specs','--assert-strict','--assert',
         'typedef typedef int (*Callback)(unsigned char);']
 for name,pc,code,prototype in entries:
  common+=['--addr',hex(pc),'--define-function',f'{pc:#x}-{pc+len(code):#x}={name}','--assert','prototype '+name+' '+prototype]
 common+=['--assert','data 0x1300 Callback callback_slot']
 meta=invoke([args.cli,'decompile-all',binary,'--json',*common]);assert meta['status']==0,meta
 metadata=json.loads(meta['stdout'])
 assert {f['name']for f in metadata['functions']}=={entry[0]for entry in entries},metadata
 caller=next(f for f in metadata['functions'] if f['name']==entries[0][0])
 assert caller.get('error') is None and caller.get('code'),caller
 project=invoke([args.cli,'decompile-project',binary,'-o',args.out/'project',*common])
 record_unrepresented_admission(report,project,'preserved_rax85',['EX03','EX04','EX12'])
 assert 'invoke(' in caller['code'] and 'callback_slot' in caller['code'],caller
 report['behavioral_checks_completed']=True
 report['raw_state']={'original_machine_preserved_rax':85}
 report['completed']=True
except BaseException:
 report['failure']=traceback.format_exc()
 raise
finally:
 (args.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report,indent=2))
