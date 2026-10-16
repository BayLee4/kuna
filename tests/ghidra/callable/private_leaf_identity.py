#!/usr/bin/env python3
"""Authentic ELF identity-definition publication across serial, stream and workers."""
import argparse
import hashlib
import json
from pathlib import Path
from support import ROOT, tool, require_provider_body, require_absent_provider_body
import subprocess
import traceback
from whole_calls_workers import ElfMachine,elf_symbols

parser=argparse.ArgumentParser();parser.add_argument('--cli',type=Path,required=True);parser.add_argument('--binary',type=Path,required=True);parser.add_argument('--out',type=Path,required=True);args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=False)
report={'scope':'Unchanged-ABI private leaf, authentic ELF/DWARF, actual generated C/H.','cli_sha256':hashlib.sha256(args.cli.read_bytes()).hexdigest(),'elf_sha256':hashlib.sha256(args.binary.read_bytes()).hexdigest(),'completed':False,'modes':[]}
symbols=elf_symbols(args.binary)
machine=ElfMachine(args.binary,args.out)
try:
 from jpype import JArray,JByte
 from ghidra.program.flatapi import FlatProgramAPI
 api=FlatProgramAPI(machine.program,machine.monitor);tx=machine.program.startTransaction('separate memory for genuine pointer formal')
 try:api.createMemoryBlock('identity_data',machine.address(0x6000),JArray(JByte)(bytes(8)),False)
 finally:machine.program.endTransaction(tx,True)
 observations=[]
 for initial in [0,(1<<64)-1]:
  emulator=machine.EmulatorHelper(machine.program)
  try:
   emulator.writeRegister('RDI',0x6000);emulator.writeRegister('RBP',0x1122334455667788);emulator.writeRegister('RSP',0x7fe0)
   emulator.writeMemory(machine.address(0x6000),JArray(JByte)(initial.to_bytes(8,'little')))
   emulator.writeMemory(machine.address(0x7fe0),JArray(JByte)((0x7ff0).to_bytes(8,'little')))
   emulator.setBreakpoint(machine.address(0x7ff0));assert emulator.run(machine.address(symbols['dispatch']),None,machine.monitor),str(emulator.getLastError())
   result=int(str(emulator.readRegister('RAX')))&((1<<64)-1)
   saved=int(str(emulator.readRegister('RBP')))&((1<<64)-1)
   memory=int.from_bytes(bytes(int(v)&255 for v in emulator.readMemory(machine.address(0x6000),8)),'little')
   assert emulator.getExecutionAddress()==machine.address(0x7ff0) and result==42 and saved==0x1122334455667788 and memory==7,(result,saved,memory)
   observations.append({'initial_data':initial,'result':result,'stored':memory,'outer_RBP_restored':saved})
  finally:emulator.dispose()
 report['original_machine']=observations
finally:machine.close()

for mode in ['serial','stream','jobs2']:
 out=args.out/mode;out.mkdir();row={'mode':mode,'completed':False,'commands':[]};report['modes'].append(row)
 jobs=['--jobs','2']if mode=='jobs2'else[];stream=['--stream']if mode=='stream'else[]
 def invoke(command):
  command=list(map(str,command));p=subprocess.run(command,cwd='/tmp',capture_output=True,text=True,timeout=240)
  value={'command':command,'status':p.returncode,'stdout':p.stdout,'stderr':p.stderr};row['commands'].append(value);return value
 failures=[]
 for label in ['complete','omitted']:
  try:
   names=['dispatch','subject']if label=='complete'else['dispatch']
   common=['--functions',','.join(names),*jobs,'--language','c']
   meta=invoke([args.cli,'decompile-all',args.binary,'--json',*common]);assert meta['status']==0,meta
   metadata=json.loads(meta['stdout']);(out/(label+'-metadata.json')).write_text(json.dumps(metadata,indent=2)+'\n')
   assert len(metadata['functions'])==len(names) and {f['name']for f in metadata['functions']}==set(names),metadata
   assert all(f.get('error')is None and f.get('code')for f in metadata['functions']),metadata
   for f in metadata['functions']:
    parameters=sorted((v for v in f['variables']if v['kind']=='arg'),key=lambda v:v['arg_index'])
    assert [(p['name'],p['size'],p['arg_index'])for p in parameters]==[('slot',8,0)],parameters
   project=out/(label+'-project');export=invoke([args.cli,'decompile-project',args.binary,'-o',project,*common,*stream])
   if label=='omitted':
    assert export['status']==0,export
    assert all(f['address']!=symbols['subject']for f in metadata['functions']),metadata
    require_provider_body(project/(args.binary.name+'.c'),'dispatch')
    require_absent_provider_body(project/(args.binary.name+'.c'),'subject')
    row['partial_export']={'selected_body':'dispatch','omitted':'subject','status':export['status']}
    continue
   assert export['status']==0,export
   for name in ('dispatch','subject'):
    require_provider_body(project/(args.binary.name+'.c'),name)
   stem=args.binary.name;driver=out/'consumer.c';driver.write_text('#include "'+stem+'.h"\n#include <stdint.h>\n#include <stdlib.h>\n#include <string.h>\nint main(void){ for(unsigned i=0;i<2;++i){void *slot=malloc(8);if(!slot)return 1;memset(slot,i?255:0,8);uint64_t got=dispatch(slot),stored=0;memcpy(&stored,slot,8);free(slot);if(got!=42||stored!=7)return 2;}return 0;}\n')
   row['emitted_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in [project/(stem+'.c'),project/(stem+'.h')]}
   for opt in ['-O0','-O2']:
    exe=out/('consumer'+opt);built=invoke([tool('cc'),'-std=c11','-Wall','-Wextra','-Werror=uninitialized','-Werror=incompatible-pointer-types','-Werror=implicit-function-declaration',opt,'-I',project,project/(stem+'.c'),driver,'-o',exe]);assert built['status']==0,built
    ran=invoke([exe]);assert ran['status']==0,ran
   row['identity_body_closed']=True
  except BaseException:failures.append({'phase':label,'failure':traceback.format_exc()})
 row['failures']=failures;row['behavioral_checks_completed']=not failures
 row['completed']=not failures
 (out/'report.json').write_text(json.dumps(row,indent=2)+'\n');print(json.dumps({'mode':mode,'completed':row['completed'],'failures':failures}),flush=True)
report['completed']=all(row['completed']for row in report['modes'])
(args.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
if not report['completed']:raise SystemExit(1)
