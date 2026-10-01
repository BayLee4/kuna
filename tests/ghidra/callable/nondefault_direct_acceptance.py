#!/usr/bin/env python3
"""Actual mapped-direct publication; unchanged C/H compiled and executed as i386.

No ARM ignored-attribute execution, no copied providers/prototype adapters.
Convention-print off tests the public unannotated C contract, not physical ABI retention.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
from support import tool
import re
import subprocess
import sys
import traceback
from whole_calls_workers import ElfMachine

p=argparse.ArgumentParser()
p.add_argument('--phase',choices=['cli','host'],required=True)
p.add_argument('--binary',type=Path,required=True)
p.add_argument('--out',type=Path,required=True)
p.add_argument('--native',type=Path,required=True)
p.add_argument('--sha256',required=True)
p.add_argument('--nested',action='store_true')
a=p.parse_args();a.native=a.native.resolve();a.binary=a.binary.resolve();a.out=a.out.resolve();a.out.mkdir(parents=True,exist_ok=False)
repo=Path(__file__).resolve().parents[3]
r={'completed':False,'phase':a.phase,'nested':a.nested,'native_sha256':hashlib.sha256(a.native.read_bytes()).hexdigest(),'binary_sha256':hashlib.sha256(a.binary.read_bytes()).hexdigest(),'cases':[],'off_scope':'Unannotated public C consistency; not retention of original nondefault physical ABI.'}
assert r['native_sha256']==a.sha256
clang=tool('clang');lld=tool('ld.lld')

def save():
 (a.out/'report.json').write_text(json.dumps(r,indent=2)+'\n')

def invoke(row,command):
 command=list(map(str,command));q=subprocess.run(command,cwd='/tmp',capture_output=True,text=True,timeout=240)
 v={'command':command,'status':q.returncode,'stdout':q.stdout,'stderr':q.stderr};row.setdefault('commands',[]).append(v);save();return v

def execute_emitted(row,directory,header,body,names,default_stdcall,driver_body=None):
 row['emitted_sha256']={path.name:hashlib.sha256(path.read_bytes()).hexdigest()for path in [header,body]}
 driver=directory/'consumer.c'
 checks=''.join('if('+name+'(x)!=x+7)return '+str(index+1)+';'for index,name in enumerate(names))
 if driver_body is None:driver_body='int main(void){static const int values[]={-11,-3,0,9,100};for(unsigned i=0;i<5;i++){int x=values[i];'+checks+'}return 0;}\n'
 driver.write_text('#include "'+header.name+'"\n'+driver_body)
 for opt in ['-O0','-O2']:
  case=directory/opt[1:];case.mkdir();objects=[]
  for source in [body,driver]:
   obj=case/(source.stem+'.o');objects.append(obj)
   command=[clang,'--target=i386-unknown-linux-gnu','-std=c11','-ffreestanding','-fms-extensions','-fno-builtin','-fno-stack-protector','-fno-pic','-fno-pie','-Wall','-Werror=uninitialized','-Werror=ignored-attributes','-Werror=incompatible-pointer-types','-Werror=implicit-function-declaration',opt,'-I',header.parent]
   if default_stdcall:command+=['-mrtd','-fshort-wchar']
   result=invoke(row,[*command,'-c',source,'-o',obj]);assert result['status']==0,result
  image=case/'consumer.elf';result=invoke(row,[lld,'-m','elf_i386','--image-base=0','-Ttext=0x1000','-e','main','--build-id=none',*objects,'-o',image]);assert result['status']==0,result
  result=invoke(row,[tool('llvm-objdump'),'-d',image]);assert result['status']==0,result
  m=ElfMachine(image,case)
  try:
   from java.math import BigInteger
   from jpype import JArray,JByte
   assert str(m.program.getLanguageID())=='x86:LE:32:default'
   symbols={str(s.getName()):int(s.getAddress().getOffset())for s in m.program.getSymbolTable().getAllSymbols(True)}
   e=m.EmulatorHelper(m.program)
   try:
    preserved=[('EBP',0x11223344),('EBX',42),('ESI',0x12345678),('EDI',0x23456789)]
    for register,value in [('ESP',0x7fdc),*preserved]:e.writeRegister(register,BigInteger(str(value)))
    e.writeMemory(m.address(0x7fdc),JArray(JByte)((0x7ff0).to_bytes(4,'little')));e.setBreakpoint(m.address(0x7ff0))
    assert e.run(m.address(symbols['main']),None,m.monitor),str(e.getLastError())
    assert e.getExecutionAddress()==m.address(0x7ff0)
    actual=int(str(e.readRegister('EAX')))&0xffffffff;assert actual==0,actual
    assert int(str(e.readRegister('ESP')))==0x7fe0
    for register,value in preserved:assert int(str(e.readRegister(register)))==value
    row.setdefault('execution',[]).append({'optimization':opt,'target':'i386-unknown-linux-gnu','default':'stdcall (-mrtd)'if default_stdcall else'cdecl','actual_main_EAX':actual,'final_ESP':0x7fe0,'binary_sha256':hashlib.sha256(image.read_bytes()).hexdigest()});save()
   finally:e.dispose()
  finally:m.close()

def check_print(row,header,body,names,printing,host=False):
 # Validate actual public header and actual source declarations/definitions together.
 # The compiler then checks compatibility and real x86 execution checks cleanup/storage.
 texts=[header.read_text(),body.read_text()]
 for text in texts:
  for name in names:
   declarations=re.findall(r'(?:^|\n)\s*(?:extern\s+)?int\s+(?:(?:__cdecl|__stdcall|__fastcall)\s+)?'+name+r'\s*\([^;{}]*?\)\s*(?=[;{])',text)
   assert declarations,(name,text)
   for declaration in declarations:
    convention=('__cdecl'if name.startswith('caller_')else'__stdcall'if name.endswith('_std')else'__fastcall')
    expected=printing and convention!=('__stdcall'if host else'__cdecl')
    if expected:assert convention in declaration,(convention,declaration)
    if not printing:assert not re.search(r'__(cdecl|stdcall|fastcall)\b',declaration),declaration
 row['print_consistency']=True

def cli():
 assertions=['--assert-strict']
 names=['caller_std','target_std','caller_fast','target_fast']
 for name in names:
  convention='__cdecl'if name.startswith('caller_')else'__stdcall'if name.endswith('_std')else'__fastcall'
  assertions+=['--assert','prototype '+name+' int '+convention+' '+name+'(int value)']
 for printing in [True,False]:
  for suffix in ['std','fast']:
   caller='caller_'+suffix;target='target_'+suffix;directory=a.out/(suffix+('-on'if printing else'-off'));directory.mkdir()
   row={'model':'__stdcall'if suffix=='std'else'__fastcall','printing':printing,'completed':False};r['cases'].append(row)
   try:
    common=['--target','x86:LE:32:default:windows','--language','c','--option','defaultprototype','__cdecl','--option','conventionprinting','on'if printing else'off',*assertions]
    for missing in [True,False]:
     selected=[caller]if missing else[caller,target];label='missing'if missing else'full'
     result=invoke(row,[a.native,'decompile-all',a.binary,'--json','--functions',','.join(selected),*common]);assert result['status']==0,result
     metadata=json.loads(result['stdout']);(directory/(label+'-metadata.json')).write_text(json.dumps(metadata,indent=2)+'\n')
     functions=metadata['functions'];assert len(functions)==len(selected)
     assert all(f.get('error')is None and f.get('code')and f.get('callable_export_error')is None for f in functions),metadata
     artifacts=[artifact for f in functions for artifact in f.get('callable_artifacts',[])]
     required=[artifact for artifact in artifacts if artifact.get('required')];assert required,metadata
     project=directory/label;export=invoke(row,[a.native,'decompile-project',a.binary,'-o',project,'--functions',','.join(selected),*common])
     if missing:
      assert export['status']!=0,export
      owners={artifact['key']for artifact in artifacts if artifact.get('definition')is not None}
      assert any(artifact['key']not in owners for artifact in required),artifacts
      row['missing_actual_provider_refused']=True
     else:
      assert export['status']==0,export
      owners=[artifact for f in functions if f['name']==target for artifact in f.get('callable_artifacts',[])if artifact.get('definition')is not None]
      assert any(owner['key']==required_artifact['key']for owner in owners for required_artifact in required),artifacts
      header=project/(a.binary.name+'.h');body=project/(a.binary.name+'.c')
      check_print(row,header,body,selected,printing)
      execute_emitted(row,directory,header,body,selected,False)
    row['completed']=True
   except BaseException:row['failure']=traceback.format_exc()
   save()

def cli_nested():
 declarations=[
  'typedef typedef int __stdcall StdCode(int value);',
  'typedef typedef StdCode *StdFn;',
  'typedef typedef int __fastcall FastCode(int value);',
  'typedef typedef FastCode *FastFn;',
  'typedef typedef StdFn __fastcall ChooserCode(FastFn probe);',
  'typedef typedef ChooserCode *ChooserFn;',
  'prototype target_std int __stdcall target_std(int value)',
  'prototype target_fast int __fastcall target_fast(int value)',
  'prototype choose_std StdFn __fastcall choose_std(FastFn probe)',
  'prototype nested_identity ChooserFn __cdecl nested_identity(ChooserFn chooser)',
 ]
 assertions=['--assert-strict']
 for declaration in declarations:assertions+=['--assert',declaration]
 names=['target_std','target_fast','choose_std','nested_identity']
 driver_body='''int main(void) {
 static const int values[]={-11,-3,0,9,100};
 StdCode *standard=target_std;
 FastCode *fast=target_fast;
 ChooserCode *chooser=nested_identity(choose_std);
 if(chooser!=choose_std)return 1;
 for(unsigned i=0;i<5;i++) {
  int x=values[i];
  StdCode *selected=chooser(fast);
  if(selected!=standard)return 2;
  if(standard(x)!=x+7)return 3;
  if(fast(x)!=x+7)return 4;
  if(selected(x)!=x+7)return 5;
 }
 return 0;
}
'''
 for printing in [True,False]:
  directory=a.out/('nested-on'if printing else'nested-off');directory.mkdir()
  row={'printing':printing,'completed':False,'original_source_declarations':declarations,'scope':'Actual named function Code typedefs, pointer aliases, fastcall factory returning stdcall callback, real identity function and both original callees.'};r['cases'].append(row)
  try:
   common=['--target','x86:LE:32:default:windows','--functions',','.join(names),'--language','c','--option','structdefs','on','--option','defaultprototype','__cdecl','--option','conventionprinting','on'if printing else'off',*assertions]
   result=invoke(row,[a.native,'decompile-all',a.binary,'--json',*common]);assert result['status']==0,result
   metadata=json.loads(result['stdout']);(directory/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
   assert len(metadata['functions'])==len(names)
   assert all(f.get('error')is None and f.get('code')and f.get('callable_export_error')is None for f in metadata['functions']),metadata
   project=directory/'project';result=invoke(row,[a.native,'decompile-project',a.binary,'-o',project,*common]);assert result['status']==0,result
   header=project/(a.binary.name+'.h');body=project/(a.binary.name+'.c')
   row['emitted_callable_typedefs']=[line for line in header.read_text().splitlines()if line.startswith('typedef ')and any(name in line for name in ['StdCode','StdFn','FastCode','FastFn','ChooserCode','ChooserFn'])]
   # The actual compiler enforces compatibility against genuine target and factory
   # declarations; the real i386 execution then observes both cleanup/input ABIs.
   execute_emitted(row,directory,header,body,[],False,driver_body)
   row['completed']=True
  except BaseException:row['failure']=traceback.format_exc()
  save()

def host():
 import pyghidra
 pyghidra.start()
 sys.path.insert(0,str(repo/'tests'/'ghidra'))
 from kuna_vs_stock import get_exepath_field
 from jpype import JArray
 from java.io import File,StringWriter
 from ghidra.app.decompiler import CallableSupport,DecompInterface,DecompileOptions
 from ghidra.app.util.exporter import CppExporter
 from ghidra.program.model.data import IntegerDataType
 from ghidra.program.model.listing import Function,ParameterImpl,ReturnParameterImpl,Variable
 from ghidra.program.model.symbol import SourceType
 from ghidra.util.task import ConsoleTaskMonitor
 field=get_exepath_field();old=field.get(None);field.set(None,str(a.native))
 try:
  with pyghidra.open_program(a.binary,project_location=a.out,project_name='host-windows',language='x86:LE:32:default',compiler='windows',analyze=False)as api:
   program=api.getCurrentProgram();monitor=ConsoleTaskMonitor();functions={}
   assert str(program.getCompilerSpec().getDefaultCallingConvention().getName())=='__stdcall'
   transaction=program.startTransaction('Original cdecl caller and real nondefault target models')
   try:
    for symbol in program.getSymbolTable().getAllSymbols(True):
     name=str(symbol.getName())
     if name not in ['caller_std','target_std','caller_fast','target_fast']:continue
     address=symbol.getAddress();api.disassemble(address)
     function=program.getFunctionManager().getFunctionAt(address)
     if function is None:function=api.createFunction(address,name)
     convention='__cdecl'if name.startswith('caller_')else'__stdcall'if name.endswith('_std')else'__fastcall'
     function.updateFunction(convention,ReturnParameterImpl(IntegerDataType.dataType,program),Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,False,SourceType.USER_DEFINED,JArray(Variable)([ParameterImpl('value',IntegerDataType.dataType,program)]));functions[name]=function
   finally:program.endTransaction(transaction,True)
   assert len(functions)==4
   before={name:str(fn.getSignature())for name,fn in functions.items()};r['host_original_signatures']=before
   for printing in [True,False]:
    directory=a.out/('host-on'if printing else'host-off');directory.mkdir();row={'printing':printing,'completed':False,'compiler_default':'Actual Windows cspec __stdcall and wchar16, matched by clang -mrtd -fshort-wchar'};r['cases'].append(row)
    try:
     options=DecompileOptions();options.setConventionPrint(printing);interface=DecompInterface();interface.setOptions(options)
     publication=CallableSupport.Publication()
     try:
      assert interface.openProgram(program),str(interface.getLastMessage())
      for name in ['caller_std','target_std','caller_fast','target_fast']:
       result=interface.decompileFunction(functions[name],120,monitor);assert result.decompileCompleted(),str(result.getErrorMessage())
       support=result.getCallableSupport();assert support.isPresent();support=support.get();assert str(support.getStatus())=='COMPLETE',str(support.getReason())
       row.setdefault('support',[]).append({'root':name,'bodies':[{'space':int(b.id().space()),'address':int(b.id().byteAddress()),'current':bool(b.current()),'declaration':str(b.declaration()),'artifacts':[{'key':str(x.key()),'required':bool(x.required()),'kind':str(x.kind())}for x in b.artifacts()]}for b in support.getBodies()]})
       publication.add(support)
      publication.validate();header=StringWriter();body=StringWriter();publication.writeTypes(header);publication.writeDeclarations(header,True);publication.writeBodies(body)
      h=directory/'direct.h';c=directory/'direct.c';h.write_text(str(header.toString()));c.write_text('#include "direct.h"\n'+str(body.toString()))
     finally:publication.close();interface.dispose()
     check_print(row,h,c,list(functions),printing,True)
     direct=directory/'direct-execution';direct.mkdir();execute_emitted(row,direct,h,c,list(functions),True)
     exporter=CppExporter(options,True,True,True,True,False,'');assert exporter.export(File(str(directory/'whole.c')),program,None,monitor)
     h=directory/'whole.h';c=directory/'whole.c';check_print(row,h,c,list(functions),printing,True)
     whole=directory/'whole-execution';whole.mkdir();execute_emitted(row,whole,h,c,list(functions),True)
     assert {name:str(fn.getSignature())for name,fn in functions.items()}==before
     row['completed']=True
    except BaseException:row['failure']=traceback.format_exc()
    save()
 finally:field.set(None,old)

try:
 if a.nested:
  assert a.phase=='cli','Nested fixture uses the actual CLI Windows source parser'
  cli_nested()
 elif a.phase=='cli':cli()
 else:host()
 r['completed']=bool(r['cases'])and all(row['completed']for row in r['cases'])
except BaseException:r['failure']=traceback.format_exc()
finally:save();print(json.dumps({'completed':r['completed'],'cases':len(r['cases']),'failure':r.get('failure')}))
if not r['completed']:raise SystemExit(1)
