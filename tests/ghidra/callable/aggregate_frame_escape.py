#!/usr/bin/env python3
"""Native aggregate JOIN argument must expose its saved-frame pointer component."""
import argparse
import hashlib
import json
from pathlib import Path
from support import ROOT, cli as default_cli, output, tool, require_provider_body
import re
import subprocess
import traceback
from whole_calls import Machine

parser=argparse.ArgumentParser()
parser.add_argument('--cli',type=Path)
parser.add_argument('--out',type=Path)
parser.add_argument('--machine-only',action='store_true')
args=parser.parse_args()
args.cli = args.cli.resolve() if args.cli else None if args.machine_only else default_cli()
args.out = (args.out or output("aggregate_frame_escape")/"run").resolve()
args.out.mkdir(parents=True,exist_ok=False)
report={'completed':False,'machine_only':args.machine_only,'cli_sha256':None if args.cli is None else hashlib.sha256(args.cli.read_bytes()).hexdigest(),'scope':'Default x86-64 gcc aggregate JOIN ABI, genuine writer machine body, native callback mutable LOAD, saved-frame alias negative and disjoint-memory strict positive. No substituted C callee or native signature casts.','cases':[]}
for name in ['saved_frame','disjoint']:
 out=args.out/name;out.mkdir()
 row={'case':name,'completed':False,'commands':[]};report['cases'].append(row)
 def invoke(command):
  command=list(map(str,command));p=subprocess.run(command,cwd='/tmp',capture_output=True,text=True,timeout=240)
  result={'command':command,'status':p.returncode,'stdout':p.stdout,'stderr':p.stderr};row['commands'].append(result);return result
 try:
  subject=bytes.fromhex('55'+('4889e7'if name=='saved_frame'else'')+'be07000000')
  subject+=bytes.fromhex('488b05')+(0x1300-(0x1100+len(subject)+7)).to_bytes(4,'little',signed=True)
  subject+=bytes.fromhex('ffd05dc3')
  entries=[('dispatch',0x1000,bytes.fromhex('55bd2a000000e8f50000004889e85dc3'),''),('subject',0x1100,subject,''),('writer',0x1200,bytes.fromhex('488937c3'),'')]
  image=bytearray(0x308)
  for _,pc,code,_ in entries:image[pc-0x1000:pc-0x1000+len(code)]=code
  image[0x300:0x308]=(0x1200).to_bytes(8,'little')
  row['instructions']=[{'name':n,'entry':pc,'bytes':code.hex()}for n,pc,code,_ in entries]
  binary=out/'aggregate_frame';binary.write_bytes(image)
  machine=Machine(image,entries)
  try:
   from jpype import JArray,JByte
   from ghidra.program.flatapi import FlatProgramAPI
   from ghidra.program.model.data import VoidDataType,UnsignedLongLongDataType,PointerDataType,StructureDataType,FunctionDefinitionDataType,ParameterDefinition,ParameterDefinitionImpl
   from ghidra.program.model.listing import Function,ParameterImpl,ReturnParameterImpl,Variable
   from ghidra.program.model.symbol import SourceType
   program=machine.program;api=FlatProgramAPI(program,machine.monitor);dtm=program.getDataTypeManager()
   wide=UnsignedLongLongDataType.dataType;void=VoidDataType.dataType;pointer=PointerDataType(wide,dtm)
   pair=StructureDataType('Pair',0,dtm);pair.add(pointer,'slot',None);pair.add(wide,'tag',None)
   assert pair.getLength()==16 and [c.getOffset()for c in pair.getComponents()]==[0,8]
   definition=FunctionDefinitionDataType('Writer',dtm);definition.setCallingConvention('__stdcall');definition.setReturnType(void)
   definition.setArguments(JArray(ParameterDefinition)([ParameterDefinitionImpl('value',pair,None)]))
   callback=PointerDataType(definition,dtm)
   tx=program.startTransaction('genuine aggregate native source ABI')
   try:
    api.createMemoryBlock('disjoint_data',machine.address(0x6000),JArray(JByte)(bytes(8)),False)
    program.getMemory().getBlock(machine.address(0x1300)).setWrite(True)
    api.createData(machine.address(0x1300),callback);api.createLabel(machine.address(0x1300),'callback_slot',True)
    row['source']=[]
    for fn_name,pc,_,_ in entries:
     fn=api.createFunction(machine.address(pc),fn_name);assert fn is not None
     parameters=[ParameterImpl('value',pair,program)]if fn_name=='writer'else[ParameterImpl('slot',pointer,program)]if name=='disjoint'else[]
     result=wide if fn_name=='dispatch'else void
     fn.updateFunction('__stdcall',ReturnParameterImpl(result,program),Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,False,SourceType.USER_DEFINED,JArray(Variable)(parameters))
     params=[]
     for p in fn.getParameters():
      pieces=[{'register':str(program.getRegister(v.getAddress(),v.getSize()).getName()),'size':int(v.getSize()),'offset':int(v.getOffset())}for v in p.getVariableStorage().getVarnodes()]
      params.append({'name':str(p.getName()),'type':str(p.getDataType()),'size':int(p.getDataType().getLength()),'storage':str(p.getVariableStorage()),'pieces':pieces})
     if fn_name=='writer':
      assert len(params)==1 and params[0]['size']==16 and {(p['register'],p['size'])for p in params[0]['pieces']}=={('RDI',8),('RSI',8)},params
     row['source'].append({'name':fn_name,'signature':str(fn.getSignature()),'parameters':params,'return_storage':str(fn.getReturn().getVariableStorage())})
    row['callback_slot_mutable']=bool(program.getMemory().getBlock(machine.address(0x1300)).isWrite())
   finally:program.endTransaction(tx,True)
   row['machine']=[]
   for initial in [0,(1<<64)-1]:
    emulator=machine.EmulatorHelper(program)
    try:
     for register,value in [('RDI',0x6000),('RBP',0x1122334455667788),('RSP',0x7fe0)]:emulator.writeRegister(register,value)
     emulator.writeMemory(machine.address(0x6000),JArray(JByte)(initial.to_bytes(8,'little')))
     emulator.writeMemory(machine.address(0x7fe0),JArray(JByte)((0x7ff0).to_bytes(8,'little')))
     emulator.setBreakpoint(machine.address(0x7ff0));assert emulator.run(machine.address(0x1000),None,machine.monitor),str(emulator.getLastError())
     assert emulator.getExecutionAddress()==machine.address(0x7ff0)
     got=int(str(emulator.readRegister('RAX')))&((1<<64)-1);rbp=int(str(emulator.readRegister('RBP')))&((1<<64)-1)
     stored=int.from_bytes(bytes(int(v)&255 for v in emulator.readMemory(machine.address(0x6000),8)),'little')
     assert got==(7 if name=='saved_frame'else 42)and rbp==0x1122334455667788 and stored==(initial if name=='saved_frame'else 7),(name,got,rbp,stored)
     row['machine'].append({'initial_disjoint_memory':initial,'outer_result':got,'outer_RBP_restored':rbp,'disjoint_memory':stored})
    finally:emulator.dispose()
  finally:machine.close()
  if args.machine_only:row['completed']=True;continue
  common=['--raw-image','--target','x86:LE:64:default:gcc','--base','0x1000','--sleighpath',ROOT/'specs','--assert-strict','--assert','typedef typedef struct Pair { unsigned long long *slot; unsigned long long tag; } Pair;','--assert','typedef typedef void (*Writer)(Pair value);','--assert','data 0x1300 Writer callback_slot']
  declarations={'dispatch':'unsigned long long dispatch('+('unsigned long long *slot'if name=='disjoint'else'void')+')','subject':'void subject('+('unsigned long long *slot'if name=='disjoint'else'void')+')','writer':'void writer(Pair value)'}
  for fn_name,pc,code,_ in entries:common+=['--addr',hex(pc),'--define-function',f'{pc:#x}-{pc+len(code):#x}={fn_name}','--assert','prototype '+fn_name+' '+declarations[fn_name]]
  meta=invoke([args.cli,'decompile-all',binary,'--json',*common]);assert meta['status']==0,meta
  metadata=json.loads(meta['stdout']);(out/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
  byname={f['name']:f for f in metadata['functions']};assert len(metadata['functions'])==len(entries) and set(byname)=={entry[0]for entry in entries},metadata
  assert all(f.get('error')is None and f.get('code')for f in byname.values()),metadata
  project=out/'project';export=invoke([args.cli,'decompile-project',binary,'-o',project,*common])
  if name=='saved_frame':
   row['executable_extension_contract']='EX11/EX12 historical refusal remains prerequisite-unrepresented; ordinary export status is not executable certification'
  if name=='disjoint':
   assert export['status']==0,export
   for provider,_,_,_ in entries:require_provider_body(project/'aggregate_frame.c',provider)
   header=(project/'aggregate_frame.h').read_text()
   declaration=re.search(r'(?m)^\s*extern\s+Writer\s+callback_slot\s*;',header);assert declaration,header
   writer_address=next(pc for fn_name,pc,_,_ in entries if fn_name=='writer')
   original_slot=bytes(image[0x300:0x308]);assert int.from_bytes(original_slot,'little')==writer_address
   row['original_external_data']={'address':0x1300,'size':8,'original_bytes':original_slot.hex(),'initializer_writer':writer_address,'declaration':declaration.group().strip()}
   data=out/'fixture-data.c';data.write_text('#include "aggregate_frame.h"\nWriter callback_slot=writer;\n')
   row['emitted_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in [project/'aggregate_frame.c',project/'aggregate_frame.h']}
   driver=out/'consumer.c';driver.write_text('#include "aggregate_frame.h"\n#include <stdint.h>\n#include <stdlib.h>\n#include <string.h>\nint main(void){for(unsigned i=0;i<2;++i){void *slot=malloc(8);if(!slot)return 1;memset(slot,i?255:0,8);uint64_t got=dispatch(slot),stored=0;memcpy(&stored,slot,8);free(slot);if(got!=42||stored!=7)return 2;}return 0;}\n')
   for opt in ['-O0','-O2']:
    executable=out/('consumer'+opt);built=invoke([tool('cc'),'-std=c11','-Wall','-Wextra','-Werror=uninitialized','-Werror=incompatible-pointer-types','-Werror=implicit-function-declaration',opt,'-I',project,project/'aggregate_frame.c',driver,data,'-o',executable]);assert built['status']==0,built
    ran=invoke([executable]);assert ran['status']==0,ran
   row['unchanged_c_passed']=True
  row['completed']=True
 except BaseException:row['failure']=traceback.format_exc()
 finally:
  (out/'report.json').write_text(json.dumps(row,indent=2)+'\n');print(json.dumps({'case':name,'completed':row['completed'],'failure':row.get('failure')}),flush=True)
report['completed']=all(row['completed']for row in report['cases']);(args.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
if not report['completed']:raise SystemExit(1)
