#!/usr/bin/env python3
"""Real stack-tail and typed-address boundaries for finite variadic execution."""
import argparse
import hashlib
import json
from pathlib import Path
from support import ROOT, cli as default_cli, output, tool, require_provider_body, record_unrepresented_admission
import subprocess
import traceback
from whole_calls import Machine

parser=argparse.ArgumentParser();parser.add_argument('--cli',type=Path);parser.add_argument('--out',type=Path);args=parser.parse_args();args.cli = (args.cli or default_cli()).resolve(); args.out = (args.out or output("finite_variadic_boundaries")/"run").resolve()
args.out.mkdir(parents=True,exist_ok=False)
root=ROOT
report={'cli_sha256':hashlib.sha256(args.cli.read_bytes()).hexdigest(),'completed':False,'cases':[]}
cases=[('stack_tail',[('subject',0x1000,bytes.fromhex('8b442408c3'),'int subject(int tag,...)')]),('typed_address',[('maker',0x1000,bytes.fromhex('488d05f90f0000c3'),'Variadic maker(void)'),('mode_target',0x2000,bytes.fromhex('89f801f0c3'),'int mode_target(int tag,...)')])]
cases.append(('mode_target',[('mode_target',0x2000,bytes.fromhex('89f801f0c3'),'int mode_target(int tag,...)')]))
for name,entries in cases:
 out=args.out/name;out.mkdir();row={'case':name,'completed':False,'commands':[]};report['cases'].append(row)
 def invoke(command):
  command=list(map(str,command));p=subprocess.run(command,cwd='/tmp',capture_output=True,text=True,timeout=240)
  record={'command':command,'status':p.returncode,'stdout':p.stdout,'stderr':p.stderr};row['commands'].append(record);return record
 try:
  image=bytearray(max(pc+len(code)for _,pc,code,_ in entries)-0x1000)
  for _,pc,code,_ in entries:image[pc-0x1000:pc-0x1000+len(code)]=code
  machine=Machine(image,entries)
  try:
   from jpype import JArray,JByte
   from ghidra.program.flatapi import FlatProgramAPI
   from ghidra.program.model.data import IntegerDataType,FunctionDefinitionDataType,ParameterDefinition,ParameterDefinitionImpl,PointerDataType
   from ghidra.program.model.listing import Function,ParameterImpl,ReturnParameterImpl,Variable
   from ghidra.program.model.symbol import SourceType
   integer=IntegerDataType.dataType;program=machine.program;api=FlatProgramAPI(program,machine.monitor)
   callback=FunctionDefinitionDataType('Variadic',program.getDataTypeManager());callback.setCallingConvention('__stdcall');callback.setReturnType(integer);callback.setArguments(JArray(ParameterDefinition)([ParameterDefinitionImpl('tag',integer,None)]));callback.setVarArgs(True)
   pointer=PointerDataType(callback,program.getDataTypeManager());source=[]
   tx=program.startTransaction('authentic variadic declarations')
   try:
    for fn_name,pc,_,_ in entries:
     fn=api.createFunction(machine.address(pc),fn_name);assert fn is not None
     is_maker=fn_name=='maker';parameters=[]if is_maker else[ParameterImpl('tag',integer,program)]
     fn.updateFunction('__stdcall',ReturnParameterImpl(pointer if is_maker else integer,program),Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,False,SourceType.USER_DEFINED,JArray(Variable)(parameters));fn.setVarArgs(not is_maker)
     if not is_maker:assert fn.hasVarArgs()and fn.getParameterCount()==1 and str(fn.getParameter(0).getVariableStorage())=='EDI:4'
     source.append({'name':fn_name,'signature':str(fn.getSignature()),'varargs':bool(fn.hasVarArgs()),'parameters':[(str(p.getName()),str(p.getVariableStorage()),int(p.getDataType().getLength()))for p in fn.getParameters()],'return_type':str(fn.getReturnType()),'return_storage':str(fn.getReturn().getVariableStorage())})
    assert callback.hasVarArgs()and len(callback.getArguments())==1
   finally:program.endTransaction(tx,True)
   row['source']=source;row['machine']=[]
   vectors=([(0x1000,1,2,tail,tail)for tail in [0,7,0x12345678,0xffffffff]]if name=='stack_tail'else ([(0x1000,0,0,None,0x2000)]if name=='typed_address'else [])+[(0x2000,5,10,None,15),(0x2000,7,71,None,78)])
   for pc,rdi,rsi,tail,wanted in vectors:
    emulator=machine.EmulatorHelper(program)
    try:
     for register,value in [('RDI',rdi),('RSI',rsi),('RDX',3),('RCX',4),('R8',5),('R9',6),('EAX',0),('RSP',0x7fe0)]:emulator.writeRegister(register,value)
     emulator.writeMemory(machine.address(0x7fe0),JArray(JByte)((0x7ff0).to_bytes(8,'little')))
     if tail is not None:emulator.writeMemory(machine.address(0x7fe8),JArray(JByte)(tail.to_bytes(8,'little')))
     emulator.setBreakpoint(machine.address(0x7ff0));assert emulator.run(machine.address(pc),None,machine.monitor),str(emulator.getLastError());assert emulator.getExecutionAddress()==machine.address(0x7ff0)
     actual=int(str(emulator.readRegister('RAX')))&((1<<64)-1);assert actual==wanted,(name,pc,actual,wanted)
     row['machine'].append({'entry':pc,'fixed_tag_RDI':rdi,'first_tail_RSI':rsi,'incoming_stack_tail_rsp_plus8':tail,'result':actual})
    finally:emulator.dispose()
  finally:machine.close()
  binary=out/name;binary.write_bytes(image)
  common=['--raw-image','--target','x86:LE:64:default:gcc','--base','0x1000','--sleighpath',root/'specs','--assert-strict']
  if name=='typed_address':common+=['--assert','typedef typedef int (*Variadic)(int tag,...);']
  for fn_name,pc,code,prototype in entries:common+=['--addr',hex(pc),'--define-function',f'{pc:#x}-{pc+len(code):#x}={fn_name}','--assert','prototype '+fn_name+' '+prototype]
  meta=invoke([args.cli,'decompile-all',binary,'--json',*common]);assert meta['status']==0,meta
  metadata=json.loads(meta['stdout']);(out/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n');assert len(metadata['functions'])==len(entries) and {f['name']for f in metadata['functions']}=={entry[0]for entry in entries},metadata
  assert all(f.get('error')is None and f.get('code')for f in metadata['functions']),metadata
  byname={f['name']:f for f in metadata['functions']}
  for fn_name,_,_,_ in entries:
   parameters=sorted((v for v in byname[fn_name]['variables']if v['kind']=='arg'),key=lambda v:v['arg_index'])
   assert [(v['name'],v['size'])for v in parameters]==([]if fn_name=='maker'else[('tag',4)]),parameters
  if name!='mode_target':
   export=invoke([args.cli,'decompile-project',binary,'-o',out/'project',*common])
   record_unrepresented_admission(row,export,name,['EX14'])
  else:
   project=out/'target_project'
   export=invoke([args.cli,'decompile-project',binary,'-o',project,*common]);assert export['status']==0,export
   require_provider_body(project/'mode_target.c','mode_target')
   driver=out/'driver.c';driver.write_text('#include "mode_target.h"\nint main(void){return mode_target(5,10)!=15 || mode_target(7,71)!=78;}\n')
   for optimization in ['-O0','-O2']:
    executable=out/('target'+optimization)
    compiled=invoke([tool('clang'),optimization,'-I',project,project/'mode_target.c',driver,'-o',executable]);assert compiled['status']==0,compiled
    executed=invoke([executable]);assert executed['status']==0,executed
   row['standalone_target_published']=True
  row['completed']=True
 except BaseException:row['failure']=traceback.format_exc()
 finally:
  (out/'report.json').write_text(json.dumps(row,indent=2)+'\n');print(json.dumps({'case':name,'completed':row['completed'],'failure':row.get('failure')}),flush=True)
report['completed']=all(row['completed']for row in report['cases']);(args.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
if not report['completed']:raise SystemExit(1)
