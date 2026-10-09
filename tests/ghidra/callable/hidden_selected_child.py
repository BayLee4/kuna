#!/usr/bin/env python3
"""Real selected child pointer-result/load chain and unchanged provider C."""
import argparse,hashlib,json,re,subprocess,traceback
from pathlib import Path
from support import ROOT, host, require_provider_body, tool
from whole_calls_workers import ElfMachine,elf_symbols
p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--binary',type=Path,required=True);p.add_argument('--cli',type=Path);p.add_argument('--sha256');p.add_argument('--phase',choices=['machine','all'],default='all');a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False);repo=ROOT;r={'completed':False,'phase':a.phase,'scope':'Actual selected child pointer return, load, and public provider consumer','machine':[],'commands':[],'binary_sha256':hashlib.sha256(a.binary.read_bytes()).hexdigest()}
if a.phase=='all':r['cli_sha256']=hashlib.sha256(a.cli.read_bytes()).hexdigest();assert r['cli_sha256']==a.sha256
try:
 symbols=elf_symbols(a.binary);m=ElfMachine(a.binary,a.out)
 try:
  from java.math import BigInteger
  data_symbols={str(s.getName()):int(s.getAddress().getOffset())for s in m.program.getSymbolTable().getAllSymbols(True)}
  for entry in ['selected_child']:
   e=m.EmulatorHelper(m.program)
   try:
    for register,value in [('X0',0x76543210),('X19',42),('X29',0x1122334455667788),('X30',0x7ff0),('sp',0x7fe0)]:e.writeRegister(register,BigInteger(str(value)))
    e.setBreakpoint(m.address(0x7ff0));assert e.run(m.address(symbols[entry]),None,m.monitor),str(e.getLastError());got=int(str(e.readRegister('X0')));assert got==13
    assert int(str(e.readRegister('sp')))==0x7fe0 and int(str(e.readRegister('X19')))==42 and int(str(e.readRegister('X29')))==0x1122334455667788
    r['machine'].append({'entry':entry,'result':got,'final_SP':0x7fe0,'final_X19':42,'final_X29':0x1122334455667788})
   finally:e.dispose()
  if a.phase=='all':
   from jpype import JArray
   from ghidra.app.decompiler import DecompInterface
   from ghidra.program.flatapi import FlatProgramAPI
   from ghidra.program.model.data import UnsignedLongLongDataType,PointerDataType,FunctionDefinitionDataType
   from ghidra.program.model.listing import Function,ReturnParameterImpl,Variable
   from ghidra.program.model.pcode import PcodeOp
   from ghidra.program.model.symbol import SourceType
   from kuna_vs_stock import selected_core
   program=m.program;api=FlatProgramAPI(program,m.monitor);dtm=program.getDataTypeManager()
   wide=UnsignedLongLongDataType.dataType;pointer=PointerDataType(wide,dtm)
   convention=str(program.getCompilerSpec().getDefaultCallingConvention().getName())
   definition=FunctionDefinitionDataType('PtrFn',dtm);definition.setReturnType(pointer);definition.setCallingConvention(convention)
   callback=PointerDataType(definition,dtm)
   tx=program.startTransaction('Original selected-child pointer declarations')
   try:
    for name,result in [('native_pointer',pointer),('selected_child',wide)]:
     api.disassemble(m.address(symbols[name]))
     function=program.getFunctionManager().getFunctionAt(m.address(symbols[name]))
     if function is None:function=api.createFunction(m.address(symbols[name]),name)
     function.updateFunction(convention,ReturnParameterImpl(result,program),Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,False,SourceType.USER_DEFINED,JArray(Variable)([]))
    slot=m.address(data_symbols['pointer_slot']);value=m.address(data_symbols['pointer_value'])
    api.clearListing(slot,slot.add(7));api.createData(slot,callback)
    api.clearListing(value,value.add(7));api.createData(value,wide)
    original_pointer=int(program.getMemory().getLong(slot))&((1<<64)-1)
    original_value=int(program.getMemory().getLong(value))&((1<<64)-1)
    assert original_pointer==symbols['native_pointer'] and original_value==13
    r['original_pointer_data']={'pointer_slot_target':original_pointer,'pointer_value':original_value}
   finally:program.endTransaction(tx,True)
   with selected_core(host()):
    interface=DecompInterface()
    try:
     assert interface.openProgram(program)
     result=interface.decompileFunction(program.getFunctionManager().getFunctionAt(m.address(symbols['selected_child'])),60,m.monitor)
     assert result.decompileCompleted(),str(result.getErrorMessage())
     high=result.getHighFunction()
     operations=list(high.getPcodeOps())
     def peel(value):
      seen=set()
      while value is not None and value.getDef() is not None:
       operation=value.getDef()
       if operation.getOpcode() not in (PcodeOp.COPY,PcodeOp.CAST):break
       identity=str(operation.getSeqnum())
       assert identity not in seen
       seen.add(identity);value=operation.getInput(0)
      return value
     chain=[]
     for operation in operations:
      if operation.getOpcode()!=PcodeOp.RETURN:continue
      for index in range(1,operation.getNumInputs()):
       returned=peel(operation.getInput(index));load=returned.getDef() if returned is not None else None
       if load is None or load.getOpcode()!=PcodeOp.LOAD:continue
       address=peel(load.getInput(1));call=address.getDef() if address is not None else None
       if call is not None and call.getOpcode() in (PcodeOp.CALL,PcodeOp.CALLIND):
        chain.append({'call':str(call),'load':str(load),'return':str(operation)})
     assert len(chain)==1, [str(operation)for operation in operations]
     r['ordinary_high_call_result_load_return']=chain
    finally:interface.dispose()
 finally:m.close()
 if a.phase=='all':
  declarations=['typedef typedef unsigned long long *(*PtrFn)(void);','prototype selected_child unsigned long long selected_child(void)','prototype native_pointer unsigned long long *native_pointer(void)','data '+hex(data_symbols['pointer_slot'])+' PtrFn pointer_slot','data '+hex(data_symbols['pointer_value'])+' unsigned long long pointer_value']
  command=[str(a.cli),'decompile-all',str(a.binary),'--functions','selected_child','--json','--language','c','--option','structdefs','on','--assert-strict']
  for d in declarations:command+=['--assert',d]
  q=subprocess.run(command,cwd=repo,capture_output=True,text=True,timeout=240);r['commands'].append({'command':command,'status':q.returncode,'stdout':q.stdout,'stderr':q.stderr});assert q.returncode==0;meta=json.loads(q.stdout);(a.out/'metadata.json').write_text(json.dumps(meta,indent=2)+'\n');functions={f['name']:f for f in meta['functions']};assert set(functions)=={'selected_child'}
  child=functions['selected_child']
  for f in functions.values():
   assert f.get('error')is None,f
   assert re.search(r'\breturn\b',f['code']),f
  assert re.search(r'\b(?:native_pointer|pointer_slot)\b',child['code']),child
  child_common=['--functions','selected_child,native_pointer','--language','c','--option','structdefs','on','--assert-strict']
  for declaration in declarations:child_common+=['--assert',declaration]
  child_project=a.out/'child-project'
  def invoke(command):
   command=list(map(str,command));q=subprocess.run(command,cwd=repo,capture_output=True,text=True,timeout=240)
   result={'command':command,'status':q.returncode,'stdout':q.stdout,'stderr':q.stderr};r['commands'].append(result)
   assert result['status']==0,result
   return result
  invoke([a.cli,'decompile-project',a.binary,'-o',child_project,*child_common])
  stem=a.binary.name;body=child_project/(stem+'.c');header=child_project/(stem+'.h')
  for provider in ('selected_child','native_pointer'):require_provider_body(body,provider)
  data=a.out/'original-pointer-data.c'
  data.write_text('#include "'+stem+'.h"\nunsigned long long pointer_value=13;\nPtrFn pointer_slot=native_pointer;\n')
  driver=a.out/'child-consumer.c'
  driver.write_text('#include "'+stem+'.h"\nint main(void){if(native_pointer()!=&pointer_value)return 1;if(selected_child()!=13)return 2;return 0;}\n')
  r['child_emitted_sha256']={path.name:hashlib.sha256(path.read_bytes()).hexdigest()for path in (body,header)}
  for optimization in ('-O0','-O2'):
   executable=a.out/('child-consumer'+optimization)
   invoke([tool('cc'),'-std=c11','-Wall','-Wextra','-Werror=uninitialized','-Werror=incompatible-pointer-types','-Werror=implicit-function-declaration',optimization,'-I',child_project,body,data,driver,'-o',executable])
   invoke([executable])
  r['unchanged_selected_child_provider_execution']=True
 r['behavioral_checks_completed']=True
 r['completed']=True
except BaseException:r['failure']=traceback.format_exc()
finally:(a.out/'report.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'completed':r['completed'],'failure':r.get('failure')}))
if not r['completed']:raise SystemExit(1)
