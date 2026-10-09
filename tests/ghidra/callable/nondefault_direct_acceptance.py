#!/usr/bin/env python3
"""Actual mapped-direct publication; unchanged C/H compiled and executed as i386.

No ARM ignored-attribute execution, no copied providers/prototype adapters.
Convention-print off tests the public unannotated C contract, not physical ABI retention.
"""
import argparse
import hashlib
import json

from pathlib import Path
from support import execute_i386_publication, require_provider_body
import re
import subprocess
import sys
import traceback

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

def save():
 (a.out/'report.json').write_text(json.dumps(r,indent=2)+'\n')

def invoke(row,command):
 command=list(map(str,command));q=subprocess.run(command,cwd='/tmp',capture_output=True,text=True,timeout=240)
 v={'command':command,'status':q.returncode,'stdout':q.stdout,'stderr':q.stderr};row.setdefault('commands',[]).append(v);save();return v

def execute_emitted(row,directory,header,body,names,default_stdcall,driver_body=None):
 driver=directory/'consumer.c'
 checks=''.join('if('+name+'(x)!=x+7)return '+str(index+1)+';'for index,name in enumerate(names))
 if driver_body is None:driver_body='int main(void){static const int values[]={-11,-3,0,9,100};for(unsigned i=0;i<5;i++){int x=values[i];'+checks+'}return 0;}\n'
 driver.write_text('#include "'+header.name+'"\n'+driver_body)
 execute_i386_publication(row,directory,header,body,driver,default_stdcall)
 save()

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
    selected=[caller,target]
    result=invoke(row,[a.native,'decompile-all',a.binary,'--json','--functions',','.join(selected),*common]);assert result['status']==0,result
    metadata=json.loads(result['stdout']);(directory/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
    functions=metadata['functions'];assert {f['name']for f in functions}==set(selected)
    assert all(f.get('error')is None for f in functions),metadata
    project=directory/'project';export=invoke(row,[a.native,'decompile-project',a.binary,'-o',project,'--functions',','.join(selected),*common])
    assert export['status']==0,export
    header=project/(a.binary.name+'.h');body=project/(a.binary.name+'.c')
    for name in selected:require_provider_body(body,name)
    check_print(row,header,body,selected,printing)
    execute_emitted(row,directory,header,body,selected,False)
    row['behavioral_checks_completed']=True
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
   assert {f['name']for f in metadata['functions']}==set(names)
   assert all(f.get('error')is None for f in metadata['functions']),metadata
   project=directory/'project';result=invoke(row,[a.native,'decompile-project',a.binary,'-o',project,*common]);assert result['status']==0,result
   header=project/(a.binary.name+'.h');body=project/(a.binary.name+'.c')
   for name in names:require_provider_body(body,name)
   row['emitted_callable_typedefs']=[line for line in header.read_text().splitlines()if line.startswith('typedef ')and any(name in line for name in ['StdCode','StdFn','FastCode','FastFn','ChooserCode','ChooserFn'])]
   # The actual compiler enforces compatibility against genuine target and factory
   # declarations; the real i386 execution then observes both cleanup/input ABIs.
   execute_emitted(row,directory,header,body,[],False,driver_body)
   row['completed']=True
  except BaseException:row['failure']=traceback.format_exc()
  save()

def host():
 import pyghidra
 sys.path.insert(0,str(repo/'tests'/'ghidra'))
 from kuna_vs_stock import start_ghidra, selected_core, stock_executable, export_program
 start_ghidra()
 from jpype import JArray
 from ghidra.app.decompiler import DecompInterface,DecompileOptions
 from ghidra.program.model.address import AddressSet
 from ghidra.program.model.data import IntegerDataType
 from ghidra.program.model.listing import Function,ParameterImpl,ReturnParameterImpl,Variable
 from ghidra.program.model.symbol import SourceType
 from ghidra.util.task import ConsoleTaskMonitor
 for core_name,core in [('stock',stock_executable()),('kuna',a.native)]:
  with selected_core(core),pyghidra.open_program(a.binary,project_location=a.out,project_name=core_name+'-host-windows',language='x86:LE:32:default',compiler='windows',analyze=False)as api:
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
    directory=a.out/(core_name+('-host-on'if printing else'-host-off'));directory.mkdir();row={'core':core_name,'printing':printing,'completed':False,'compiler_default':'Actual Windows cspec __stdcall and wchar16, matched by clang -mrtd -fshort-wchar'};r['cases'].append(row)
    try:
     options=DecompileOptions();options.setConventionPrint(printing);interface=DecompInterface();interface.setOptions(options)
     try:
      assert interface.openProgram(program),str(interface.getLastMessage())
      for name in ['caller_std','target_std','caller_fast','target_fast']:
       result=interface.decompileFunction(functions[name],120,monitor);assert result.decompileCompleted(),str(result.getErrorMessage())
       code=str(result.getDecompiledFunction().getC())
       assert re.search(r'\breturn\b',code),(name,code)
       if name.startswith('caller_'):assert re.search(r'\btarget_'+name[7:]+r'\s*\(',code),code
       row.setdefault('ordinary_C',{})[name]=code
     finally:interface.dispose()
     selection=AddressSet()
     for function in functions.values():selection.add(function.getBody())
     assert export_program(program,directory/'direct.c',monitor,selection,options=options)
     h=directory/'direct.h';c=directory/'direct.c'
     check_print(row,h,c,list(functions),printing,True)
     direct=directory/'direct-execution';direct.mkdir();execute_emitted(row,direct,h,c,list(functions),True)
     assert export_program(program,directory/'whole.c',monitor,options=options)
     h=directory/'whole.h';c=directory/'whole.c';check_print(row,h,c,list(functions),printing,True)
     whole=directory/'whole-execution';whole.mkdir();execute_emitted(row,whole,h,c,list(functions),True)
     assert {name:str(fn.getSignature())for name,fn in functions.items()}==before
     row['completed']=True
    except BaseException:row['failure']=traceback.format_exc()
    save()

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
