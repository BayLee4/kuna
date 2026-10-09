#!/usr/bin/env python3
"""Recursive Node/Fn production acceptance with actual target callees, not C stand-ins."""
import argparse
import hashlib
import json
from pathlib import Path
from contextlib import ExitStack
import struct
import subprocess
import sys
import traceback
from whole_calls_workers import ElfMachine,elf_symbols

parser=argparse.ArgumentParser()
parser.add_argument('--out',type=Path,required=True)
parser.add_argument('--fixtures',type=Path,required=True)
parser.add_argument('--query-helpers',type=Path)
parser.add_argument('--cli',type=Path)
parser.add_argument('--cli-sha256')
parser.add_argument('--ghidra-exe',type=Path)
parser.add_argument('--ghidra-sha256')
parser.add_argument('--phase',choices=('all','machine','host','cli'),default='all')
parser.add_argument('--target',choices=('all','x86','aarch64','apple'),default='all')
parser.add_argument('--order',choices=('all','callable_first','record_first'),default='all')
args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=False)
repo=Path(__file__).resolve().parents[3];historical=args.fixtures
sys.path.insert(0,str(repo/'tests/ghidra'))
from kuna_vs_stock import export_program, selected_core, start_ghidra, stock_executable
from support import require_provider_body, snapshot, tool
report={'completed':False,'scope':'Actual target machine transform(Node)->Node and consumed callback result drive(Node,Fn)->double; unchanged emitted real transform+drive, no handwritten callback. Historical host-only execution is not reused as machine evidence.','phase':args.phase,'cases':[]}
for path,expected,key in [(args.cli,args.cli_sha256,'cli'),(args.ghidra_exe,args.ghidra_sha256,'ghidra')]:
 if path is not None:
  actual=hashlib.sha256(path.read_bytes()).hexdigest();report[key+'_sha256']=actual;report[key+'_requested_sha256']=expected
if args.phase in ['all','host']:assert args.ghidra_exe is not None and args.query_helpers is not None
if args.phase in ['all','cli']:assert args.cli is not None
vectors=[i/4 for i in range(-20,21)]
targets=[('x86',args.fixtures/'x86.elf','x86:LE:64:default'),('aarch64',args.fixtures/'aarch64.elf','AARCH64:LE:64:v8A'),('apple',historical/'production-smoke','AARCH64:LE:64:AppleSilicon')]
for name,binary,language in targets:
 if args.phase=='cli':continue
 if args.target!='all'and args.target!=name:continue
 out=args.out/name;out.mkdir();row={'target':name,'binary':str(binary),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'completed':False,'commands':[]};report['cases'].append(row)
 try:
  start_ghidra()
  row['stock_native']=stock_executable()
  machine=ElfMachine(binary,out)
  symbols=({str(s.getName()).lstrip('_'):int(s.getAddress().getOffset())for s in machine.program.getSymbolTable().getAllSymbols(True)if str(s.getName()).lstrip('_')in ['transform','drive']}if name=='apple'else elf_symbols(binary))
  row['symbols']={n:symbols[n]for n in ['transform','drive']}
  try:
   from jpype import JArray,JByte
   from java.math import BigInteger
   from ghidra.program.flatapi import FlatProgramAPI
   from ghidra.program.model.data import StructureDataType,DoubleDataType,FunctionDefinitionDataType,ParameterDefinition,ParameterDefinitionImpl,PointerDataType,DataTypeConflictHandler
   from ghidra.program.model.listing import Function,ParameterImpl,ReturnParameterImpl,Variable
   from ghidra.program.model.symbol import SourceType
   from ghidra.app.decompiler import DecompInterface,DecompileOptions,ClangFieldToken
   program=machine.program;row['language']=str(program.getLanguageID());assert row['language']==language,(row['language'],language)
   api=FlatProgramAPI(program,machine.monitor);manager=program.getDataTypeManager();functions={}
   default_model=program.getCompilerSpec().getDefaultCallingConvention()
   source_model=str(default_model.getName())
   row['compiler_model']={'compiler_spec':str(program.getCompilerSpec().getCompilerSpecID()),'default_calling_convention':source_model,'source_calling_convention':source_model}
   tx=program.startTransaction('genuine recursive mixed-class source ABI')
   try:
    node=StructureDataType('Node',16,manager);node.replaceAtOffset(0,DoubleDataType.dataType,8,'d',None)
    definition=FunctionDefinitionDataType('Fn',manager);definition.setCallingConvention(source_model);definition.setReturnType(node);definition.setArguments(JArray(ParameterDefinition)([ParameterDefinitionImpl('node',node,None)]))
    node.replaceAtOffset(8,PointerDataType(definition,manager),8,'next',None)
    node=manager.resolve(node,DataTypeConflictHandler.DEFAULT_HANDLER);callback=node.getComponentAt(8).getDataType();definition=callback.getDataType()
    assert definition.getReturnType().isEquivalent(node)and definition.getArguments()[0].getDataType().isEquivalent(node)
    row['nominal_node_id']=int(manager.getID(node));row['source']=[]
    for fn_name in ['transform','drive']:
     entry=machine.address(symbols[fn_name]);api.disassemble(entry)
     fn=program.getFunctionManager().getFunctionAt(entry)
     if fn is None:fn=api.createFunction(entry,fn_name)
     assert fn is not None;fn.setName(fn_name,SourceType.USER_DEFINED)
     params=[ParameterImpl('node',node,program)]+([ParameterImpl('callback',callback,program)]if fn_name=='drive'else[])
     result=DoubleDataType.dataType if fn_name=='drive'else node
     fn.updateFunction(source_model,ReturnParameterImpl(result,program),Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,False,SourceType.USER_DEFINED,JArray(Variable)(params));functions[fn_name]=fn
     row['source'].append({'name':fn_name,'signature':str(fn.getSignature()),'return_storage':str(fn.getReturn().getVariableStorage()),'parameters':[{'name':str(p.getName()),'size':int(p.getDataType().getLength()),'storage':str(p.getVariableStorage())}for p in fn.getParameters()]})
   finally:program.endTransaction(tx,True)
   if args.phase in ['all','machine']:
    row['original_machine']=[]
    for value in vectors:
     bits=int.from_bytes(struct.pack('<d',value),'little');wanted=value+1.0
     for fn_name in ['transform','drive']:
      emulator=machine.EmulatorHelper(program)
      try:
       if name=='x86':
        registers=[('RDI',symbols['transform']),('RSI',symbols['transform']),('XMM0',bits),('RSP',0x7fd8)]
        emulator.writeMemory(machine.address(0x7fd8),JArray(JByte)((0x7ff0).to_bytes(8,'little')))
       else:registers=[('X0',bits),('X1',symbols['transform']),('X2',symbols['transform']),('X29',0x1122334455667788),('X30',0x7ff0),('sp',0x7fe0)]
       for register,val in registers:emulator.writeRegister(register,BigInteger(str(val)))
       emulator.setBreakpoint(machine.address(0x7ff0));assert emulator.run(machine.address(symbols[fn_name]),None,machine.monitor),str(emulator.getLastError())
       assert emulator.getExecutionAddress()==machine.address(0x7ff0)
       reg='XMM0'if name=='x86'else'X0'if fn_name=='transform'else'D0'
       result_bits=int(str(emulator.readRegister(reg)))&((1<<64)-1);got=struct.unpack('<d',result_bits.to_bytes(8,'little'))[0]
       assert got==wanted,(name,fn_name,value,got,wanted)
       next_pointer=None
       if fn_name=='transform':
        next_pointer=int(str(emulator.readRegister('RAX'if name=='x86'else'X1')))&((1<<64)-1);assert next_pointer==symbols['transform']
       sp=int(str(emulator.readRegister('RSP'if name=='x86'else'sp')));assert sp==0x7fe0
       if name!='x86':assert int(str(emulator.readRegister('X29')))==0x1122334455667788
       row['original_machine'].append({'entry':fn_name,'value':value,'result':got,'returned_next':next_pointer,'final_SP':sp})
      finally:emulator.dispose()
   if args.phase in ['all','host']:
    from ghidra.program.model.pcode import PcodeOp
    helper_out=out/'helper-object';helper_out.mkdir()
    helper_object=args.query_helpers/(name+'.o');helper_machine=ElfMachine(helper_object,helper_out)
    row['query_helper_object_sha256']=hashlib.sha256(helper_object.read_bytes()).hexdigest()
    row['query_helpers']=[]
    try:
     helper_program=helper_machine.program;helper_api=FlatProgramAPI(helper_program,helper_machine.monitor)
     assert str(helper_program.getLanguageID())==language
     for fn_name,destination in [('callable_root',0x5000),('record_root',0x5100)]:
      matches=[s for s in helper_program.getSymbolTable().getAllSymbols(True)if str(s.getName()).lstrip('_')==fn_name]
      assert len(matches)==1,(fn_name,[str(s)for s in matches])
      entry=matches[0].getAddress()
      helper_tx=helper_program.startTransaction('decode authentic helper object')
      try:
       helper_program.getListing().clearCodeUnits(entry,entry.add(3),False)
       assert helper_api.disassemble(entry)
       helper_fn=helper_program.getFunctionManager().getFunctionAt(entry)
       if helper_fn is not None:helper_program.getFunctionManager().removeFunction(entry)
       helper_fn=helper_api.createFunction(entry,fn_name)
      finally:helper_program.endTransaction(helper_tx,True)
      assert helper_fn is not None
      assert not helper_program.getRelocationTable().getRelocations(helper_fn.getBody()).hasNext(),'query helper body has relocation-dependent bytes'
      length=int(helper_fn.getBody().getMaxAddress().subtract(entry))+1
      assert 0<length<=32
      data=JArray(JByte)(length);helper_program.getMemory().getBytes(entry,data)
      helper_code=bytes(int(v)&255 for v in data)
      assert helper_code==(bytes.fromhex('4889f8c3')if name=='x86'else bytes.fromhex('c0035fd6')),helper_code.hex()
      for instruction in helper_program.getListing().getInstructions(helper_fn.getBody(),True):
       assert all(op.getOpcode()not in(PcodeOp.CALL,PcodeOp.CALLIND,PcodeOp.CALLOTHER)for op in instruction.getPcode()),str(instruction)
      tx=program.startTransaction('actual typed query root helper')
      try:
       block=api.createMemoryBlock(fn_name,machine.address(destination),JArray(JByte)(helper_code),False);block.setExecute(True)
       assert api.disassemble(machine.address(destination));fn=api.createFunction(machine.address(destination),fn_name);assert fn is not None
       dtype=callback if fn_name=='callable_root'else node
       fn.updateFunction(source_model,ReturnParameterImpl(dtype,program),Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,False,SourceType.USER_DEFINED,JArray(Variable)([ParameterImpl('value',dtype,program)]))
       functions[fn_name]=fn
       row['query_helpers'].append({'name':fn_name,'original_object_address':int(entry.getOffset()),'program_address':destination,'bytes':helper_code.hex(),'source_signature':str(fn.getSignature())})
      finally:program.endTransaction(tx,True)
    finally:helper_machine.close()
    row['orders']=[]
    for order,first in [('callable_first','callable_root'),('record_first','record_root')]:
     if args.order!='all'and args.order!=order:continue
     order_out=out/order;order_out.mkdir();ordered={'order':order,'first_native_query_function':first,'completed':False,'decompilations':[],'commands':[]};row['orders'].append(ordered)
     core=ExitStack();core.enter_context(selected_core(args.ghidra_exe));ifc=DecompInterface();options=DecompileOptions();options.setNamespaceStrategy(DecompileOptions.NamespaceStrategy.Never);ifc.setOptions(options)
     before=snapshot(functions);ordered['source_before']=before
     try:
      assert ifc.openProgram(program),str(ifc.getLastMessage())
      for fn_name in [first,'transform','drive']:
       result=ifc.decompileFunction(functions[fn_name],60,machine.monitor);df=result.getDecompiledFunction();hf=result.getHighFunction();observed={'name':fn_name,'completed':bool(result.decompileCompleted()),'error':str(result.getErrorMessage()),'c':None if df is None else str(df.getC()),'fields':[]};ordered['decompilations'].append(observed)
       assert observed['completed']and df is not None and hf is not None,observed
       (order_out/(fn_name+'.c')).write_text(observed['c'])
       proto=hf.getFunctionPrototype();assert proto.getNumParams()==len(functions[fn_name].getParameters())
       observed['return_type_id']=int(manager.getID(proto.getReturnType()))
       observed['parameter_type_ids']=[int(manager.getID(proto.getParam(i).getDataType()))for i in range(proto.getNumParams())]
       for i,p in enumerate(functions[fn_name].getParameters()):assert proto.getParam(i).getDataType().isEquivalent(p.getDataType())
       expected=callback if fn_name=='callable_root'else DoubleDataType.dataType if fn_name=='drive'else node
       assert proto.getReturnType().isEquivalent(expected)
       decoded_node=proto.getParam(0).getDataType()if fn_name!='callable_root'else proto.getReturnType().getDataType().getReturnType()
       assert int(manager.getID(decoded_node))==row['nominal_node_id']
       decoded_fn=decoded_node.getComponentAt(8).getDataType().getDataType()
       assert decoded_fn.getReturnType().isEquivalent(decoded_node)and decoded_fn.getArguments()[0].getDataType().isEquivalent(decoded_node)
       observed['recursive_nominal_cycle_verified']=True
       def visit(token):
        if isinstance(token,ClangFieldToken):
         dtype=token.getDataType();observed['fields'].append({'text':str(token.getText()),'offset':int(token.getOffset()),'id':None if dtype is None else int(manager.getID(dtype))})
        for i in range(token.numChildren()):visit(token.Child(i))
       visit(result.getCCodeMarkup())
       for token in observed['fields']:
        if token['text']in ['d','next']:assert token['id']==row['nominal_node_id']and token['offset']==(0 if token['text']=='d'else 8),token
       if fn_name=='drive':
        calls=[op for op in hf.getPcodeOps()if op.getOpcode()==PcodeOp.CALLIND]
        assert len(calls)==1 and calls[0].getOutput()is not None
        target_type=calls[0].getInput(0).getHigh().getDataType()
        assert target_type.isEquivalent(callback)
        target_proto=target_type.getDataType()
        assert len(target_proto.getArguments())==1 and target_proto.getArguments()[0].getDataType().isEquivalent(node)and target_proto.getReturnType().isEquivalent(node)
        observed['actual_indirect_call']={'op':str(calls[0]),'target_type':str(target_type),'inputs':[{'varnode':str(calls[0].getInput(i)),'size':int(calls[0].getInput(i).getSize())}for i in range(calls[0].getNumInputs())],'output':str(calls[0].getOutput()),'output_size':int(calls[0].getOutput().getSize()),'logical_Node_to_Node_verified':True}
        assert calls[0].getNumInputs()==2 and calls[0].getInput(1).getSize()==16 and calls[0].getOutput().getSize()==16,observed['actual_indirect_call']
      exported=export_program(program,order_out/'unit.c',machine.monitor,options=options)
      ordered['stock_exported']=exported
      assert exported,ordered
      for fn_name in functions:require_provider_body(order_out/'unit.c',fn_name)
     except BaseException:
      ordered['failure']=traceback.format_exc()
      (order_out/'report.json').write_text(json.dumps(ordered,indent=2)+'\n')
      continue
     finally:
      ifc.dispose();core.close()
      ordered['source_after']=snapshot(functions)
      assert ordered['source_after']==before,'Export must preserve source signatures/storage'
     assert any(token['text']=='d'for d in ordered['decompilations']if d['name']in ['transform','drive']for token in d['fields']),ordered
     source=order_out/'consumer.c';source.write_text('#include "unit.h"\nint main(void){for(int i=-20;i<=20;++i){Node n={(double)i/4,transform};Node r=transform(n);if(r.d!=n.d+1||r.next!=transform)return 1;if(drive(n,transform)!=n.d+1)return 2;}return 0;}\n')
     ordered['emitted_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in [order_out/'unit.c',order_out/'unit.h']}
     for opt in ['-O0','-O2']:
      exe=order_out/('consumer'+opt)
      for command in [[tool('cc'),'-std=c11','-Wall','-Wextra','-Werror=uninitialized','-Werror=incompatible-pointer-types','-Werror=implicit-function-declaration',opt,str(order_out/'unit.c'),str(source),'-o',str(exe)],[str(exe)]]:
       p=subprocess.run(command,capture_output=True,text=True,timeout=120);record={'command':command,'status':p.returncode,'stdout':p.stdout,'stderr':p.stderr};ordered['commands'].append(record);assert p.returncode==0,record
     ordered['completed']=True
     (order_out/'report.json').write_text(json.dumps(ordered,indent=2)+'\n')
    row['unchanged_c_passed']=all(o['completed']for o in row['orders'])
   row['completed']=all(o['completed']for o in row['orders'])if args.phase in ['all','host']else True
  finally:machine.close()
 except BaseException:row['failure']=traceback.format_exc()
 finally:(out/'report.json').write_text(json.dumps(row,indent=2)+'\n');print(json.dumps({'target':name,'completed':row['completed'],'failure':row.get('failure')}),flush=True)
if args.phase in ['all','cli']:
 orders=[('callback_first',['typedef typedef struct Node Node;','typedef typedef Node (*Fn)(Node);','typedef struct Node { double d; Fn next; };']),('record_first',['typedef typedef struct Node { double d; struct Node (*next)(struct Node); } Node;','typedef typedef Node (*Fn)(Node);'])]
 for name,declarations in orders:
  out=args.out/name;out.mkdir();row={'query_order':name,'completed':False,'commands':[]};report['cases'].append(row)
  def invoke(command):
   command=list(map(str,command));p=subprocess.run(command,cwd=repo,capture_output=True,text=True,timeout=240);record={'command':command,'status':p.returncode,'stdout':p.stdout,'stderr':p.stderr};row['commands'].append(record);return record
  try:
   binary=historical/'production-smoke';common=['--functions','transform,drive','--language','c','--option','structdefs','on']
   for declaration in declarations:common+=['--assert',declaration]
   common+=['--assert','prototype transform Node transform(Node node)','--assert','prototype drive double drive(Node node,Fn callback)','--assert-strict']
   meta=invoke([args.cli,'decompile-all',binary,'--json',*common]);assert meta['status']==0,meta
   metadata=json.loads(meta['stdout']);(out/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n');assert len(metadata['functions'])==2
   assert {f['name'].lstrip('_')for f in metadata['functions']}=={'transform','drive'},metadata
   assert all(f.get('error')is None for f in metadata['functions']),metadata
   project=out/'project';export=invoke([args.cli,'decompile-project',binary,'-o',project,*common]);assert export['status']==0,export
   driver=out/'consumer.c';driver.write_text('#include "production-smoke.h"\nint main(void){for(int i=-20;i<=20;++i){Node n={(double)i/4,_transform};Node r=_transform(n);if(r.d!=n.d+1||r.next!=_transform)return 1;if(_drive(n,_transform)!=n.d+1)return 2;}return 0;}\n')
   row['emitted_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in [project/'production-smoke.c',project/'production-smoke.h']}
   for fn_name in ['_transform','_drive']:require_provider_body(project/'production-smoke.c',fn_name)
   for opt in ['-O0','-O2']:
    exe=out/('consumer'+opt);built=invoke(['cc','-std=c11','-Wall','-Wextra','-Werror=uninitialized','-Werror=incompatible-pointer-types','-Werror=implicit-function-declaration',opt,'-I',project,project/'production-smoke.c',driver,'-o',exe]);assert built['status']==0,built;ran=invoke([exe]);assert ran['status']==0,ran
   row['completed']=True
  except BaseException:row['failure']=traceback.format_exc()
  finally:(out/'report.json').write_text(json.dumps(row,indent=2)+'\n');print(json.dumps({'query_order':name,'completed':row['completed'],'failure':row.get('failure')}),flush=True)
report['completed']=all(r['completed']for r in report['cases']);(args.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
if not report['completed']:raise SystemExit(1)
