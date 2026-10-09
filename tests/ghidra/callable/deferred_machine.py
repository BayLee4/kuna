#!/usr/bin/env python3
"""Actual x86 SysV machine closures for deferred fixed-result acceptance."""
import argparse,hashlib,json,traceback
from pathlib import Path
from whole_calls_workers import ElfMachine,elf_symbols
p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--binary',type=Path,required=True);p.add_argument('--scope',choices=['original','new','entry'],default='original');a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False);r={'completed':False,'scope':a.scope,'binary_sha256':hashlib.sha256(a.binary.read_bytes()).hexdigest(),'entry_abi':'x86-64 SysV, entryRSP=0x7fd8 (mod16=8), machine return-address0x7ff0, restoredRSP=0x7fe0','cases':[]};symbols=elf_symbols(a.binary);m=ElfMachine(a.binary,a.out)
try:
 from java.math import BigInteger
 from jpype import JArray,JByte
 from ghidra.program.flatapi import FlatProgramAPI
 from ghidra.program.model.pcode import PcodeOp
 assert str(m.program.getLanguageID())=='x86:LE:64:default';api=FlatProgramAPI(m.program,m.monitor);tx=m.program.startTransaction('decode genuine loaded callback')
 try:assert api.disassemble(m.address(symbols['scalar_only_child']))
 finally:m.program.endTransaction(tx,True)
 instructions=[]
 for instruction in m.program.getListing().getInstructions(m.address(symbols['scalar_only_child']),True):
  if int(instruction.getAddress().getOffset())>=symbols['scalar_only_root']:break
  instructions.append(instruction)
 assert any(op.getOpcode()==PcodeOp.LOAD for instruction in instructions for op in instruction.getPcode())
 assert any(op.getOpcode()==PcodeOp.CALLIND for instruction in instructions for op in instruction.getPcode())
 r['scalar_only_actual_route']=[{'instruction':str(i),'address':str(i.getAddress()),'pcode':[str(op)for op in i.getPcode()]}for i in instructions]
 vectors=[]
 if a.scope=='original':
  for value in [-2,0,7,31]:
   vectors += [('scalar_root',symbols['actual_leaf'],value&0xffffffff,2*value+9,False),('scalar_only_root',value&0xffffffff,0,2*value+9,False),('returned_consumer',symbols['actual_chooser'],value&0xffffffff,2*value+1,False)]
  vectors += [(entry,symbols['actual_chooser'],0,symbols['actual_leaf'],True)for entry in ['returned_child','returned_root']]
  for depth in range(5):
   vectors += [(entry,depth,symbols['actual_leaf'],11+depth,False)for entry in ['deferred_cycle_a','deferred_cycle_b']]
   vectors += [(entry,depth,0,11+depth,False)for entry in ['ordinary_cycle_a','ordinary_cycle_b']]
 elif a.scope=='new':
  for value in [-2,0,7,31]:
   vectors += [('scalar_only_root',value&0xffffffff,0,2*value+9,False),('returned_scalar_consumer',value&0xffffffff,0,2*value+1,False)]
   vectors += [(entry,value&0xffffffff,0,symbols['actual_leaf'],True)for entry in ['returned_scalar_child','returned_scalar_root']]
  for depth in range(5):vectors += [(entry,depth,0,11+depth,False)for entry in ['scalar_cycle_a','scalar_cycle_b']]
 else:
  vectors=[('scalar_entry',value&0xffffffff,0,2*value+9,False)for value in [-11,-3,0,9,100]]
 preserved=[('RBX',42),('RBP',0x1122334455667788),('R12',1212),('R13',1313),('R14',1414),('R15',1515)]
 for entry,arg0,arg1,wanted,pointer in vectors:
  e=m.EmulatorHelper(m.program)
  try:
   for register,value in [('RDI',arg0),('RSI',arg1),('RSP',0x7fd8),*preserved]:e.writeRegister(register,BigInteger(str(value)))
   e.writeMemory(m.address(0x7fd8),JArray(JByte)((0x7ff0).to_bytes(8,'little')))
   if a.scope=='entry':
    e.setBreakpoint(m.address(symbols['scalar_root']));assert e.run(m.address(symbols[entry]),None,m.monitor),str(e.getLastError());assert e.getExecutionAddress()==m.address(symbols['scalar_root'])
    assert int(str(e.readRegister('RDI')))==symbols['actual_leaf']
    assert int(str(e.readRegister('RSI')))&0xffffffff==arg0
    e.clearBreakpoint(m.address(symbols['scalar_root']));e.setBreakpoint(m.address(0x7ff0));assert e.run(m.monitor),str(e.getLastError())
    r['actual_entry_leaf_producer']={'root':symbols['scalar_root'],'actual_leaf_RDI':symbols['actual_leaf'],'value_RSI_verified':True}
   else:
    e.setBreakpoint(m.address(0x7ff0));assert e.run(m.address(symbols[entry]),None,m.monitor),str(e.getLastError())
   assert e.getExecutionAddress()==m.address(0x7ff0)
   got=int(str(e.readRegister('RAX')))&((1<<64)-1)
   if not pointer:got=int.from_bytes((got&0xffffffff).to_bytes(4,'little'),'little',signed=True)
   assert got==wanted,(entry,arg0,arg1,got,wanted);assert int(str(e.readRegister('RSP')))==0x7fe0
   for register,value in preserved:assert int(str(e.readRegister(register)))==value,(entry,register)
   r['cases'].append({'entry':entry,'RDI':arg0,'RSI':arg1,'result':got,'pointer_result':pointer,'final_RSP':0x7fe0,'all_SysV_preserved_checked':True})
  finally:e.dispose()
 r['completed']=True
except BaseException:r['failure']=traceback.format_exc()
finally:m.close();(a.out/'report.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'completed':r['completed'],'cases':len(r['cases']),'failure':r.get('failure')}))
if not r['completed']:raise SystemExit(1)
