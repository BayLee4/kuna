#!/usr/bin/env python3
"""Original AArch64 literal/branch-selected BLR with real X8 result writes."""
import argparse,hashlib,json,traceback
from pathlib import Path
from whole_calls_workers import ElfMachine
p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.binary=a.binary.resolve();a.out=a.out.resolve();a.out.mkdir(parents=True,exist_ok=False);r={'completed':False,'binary_sha256':hashlib.sha256(a.binary.read_bytes()).hexdigest(),'cases':[],'original_raw_cfg':{},'scope':'Actual machine literal/branch-merged finite targets and raw CALLIND/branches. Public export provider execution is exercised by finite_big_acceptance.py.'};m=ElfMachine(a.binary,a.out)
try:
 from jpype import JArray,JByte
 from java.math import BigInteger
 from ghidra.program.flatapi import FlatProgramAPI
 from ghidra.program.model.pcode import PcodeOp
 assert str(m.program.getLanguageID()).startswith('AARCH64:LE:64:')
 symbols={str(s.getName()):int(s.getAddress().getOffset())for s in m.program.getSymbolTable().getAllSymbols(True)};r['symbols']=symbols
 api=FlatProgramAPI(m.program,m.monitor);tx=m.program.startTransaction('decode authentic finite BLR paths')
 try:
  for name in ['finite_static','finite_phi','make_big_a','make_big_b']:assert api.disassemble(m.address(symbols[name]))
 finally:m.program.endTransaction(tx,True)
 for name in ['finite_static','finite_phi','make_big_a','make_big_b']:
  instructions=[instruction for instruction in m.program.getListing().getInstructions(m.address(symbols[name]),True)if int(instruction.getAddress().getOffset())<symbols[name+'_end']]
  ops=[op for instruction in instructions for op in instruction.getPcode()]
  if name.startswith('finite_'):assert sum(op.getOpcode()==PcodeOp.CALLIND for op in ops)==1
  if name=='finite_phi':assert any(op.getOpcode()==PcodeOp.CBRANCH for op in ops)
  r['original_raw_cfg'][name]=[{'address':int(instruction.getAddress().getOffset()),'instruction':str(instruction),'pcode':[str(op)for op in instruction.getPcode()]}for instruction in instructions]
 mask=(1<<64)-1;preserved=[('x'+str(index),0x1111000000000000+index)for index in range(19,30)]
 for entry,selector in [('finite_static',0),('finite_phi',0),('finite_phi',1)]:
  target='make_big_b'if selector else'make_big_a'
  for tag in range(-20,21):
   e=m.EmulatorHelper(m.program)
   try:
    for register,value in [('sp',0x7fe0),('x30',0x7ff0),('x0',tag&0xffffffff),('x1',selector),*preserved]:e.writeRegister(register,BigInteger(str(value)))
    for name in ['make_big_a','make_big_b']:e.setBreakpoint(m.address(symbols[name]))
    e.setBreakpoint(m.address(0x7ff0));assert e.run(m.address(symbols[entry]),None,m.monitor),str(e.getLastError());assert e.getExecutionAddress()==m.address(symbols[target])
    call_sp=int(str(e.readRegister('sp')));hidden=int(str(e.readRegister('x8')));assert call_sp==0x7fb0 and hidden==call_sp+8
    assert int(str(e.readRegister('x16')))==symbols[target]and int(str(e.readRegister('x0')))&0xffffffff==tag&0xffffffff
    for name in ['make_big_a','make_big_b']:e.clearBreakpoint(m.address(symbols[name]))
    assert e.run(m.monitor),str(e.getLastError());assert e.getExecutionAddress()==m.address(0x7ff0)
    memory=bytes(int(x)&255 for x in e.readMemory(m.address(hidden),24));fields=[int.from_bytes(memory[offset:offset+8],'little')for offset in [0,8,16]]
    wanted=[(tag+10)&mask,11,(tag+20)&mask]if selector else[tag&mask,7,(tag+3)&mask]
    assert fields==wanted,(entry,selector,tag,fields,wanted)
    result=int(str(e.readRegister('x0')))&mask;assert result==(wanted[0]+wanted[2])&mask
    assert int(str(e.readRegister('sp')))==0x7fe0 and int(str(e.readRegister('x30')))==0x7ff0
    for register,value in preserved:assert int(str(e.readRegister(register)))==value,(entry,register)
    r['cases'].append({'entry':entry,'selector':selector,'tag':tag,'actual_target':target,'actual_target_address':symbols[target],'call_SP':call_sp,'hidden_X8':hidden,'hidden_footprint':[hidden,hidden+24],'saved_registers_start':call_sp+32,'actual_result_fields':fields,'scalar_result':result,'final_SP':0x7fe0,'preserved_X19_X29_checked':True})
   finally:e.dispose()

 r['completed']=True
except BaseException:r['failure']=traceback.format_exc()
finally:m.close();(a.out/'report.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'completed':r['completed'],'cases':len(r['cases']),'failure':r.get('failure')}))
if not r['completed']:raise SystemExit(1)
