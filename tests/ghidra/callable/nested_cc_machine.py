#!/usr/bin/env python3
"""Actual new x86-32 factory/identity pointer results, no source-body replacements."""
import argparse,hashlib,json,traceback
from pathlib import Path
from whole_calls_workers import ElfMachine
p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.binary=a.binary.resolve();a.out=a.out.resolve();a.out.mkdir(parents=True,exist_ok=False);r={'completed':False,'binary_sha256':hashlib.sha256(a.binary.read_bytes()).hexdigest(),'cases':[]};m=ElfMachine(a.binary,a.out)
try:
 from jpype import JArray,JByte
 from java.math import BigInteger
 assert str(m.program.getLanguageID())=='x86:LE:32:default'
 symbols={str(s.getName()):int(s.getAddress().getOffset())for s in m.program.getSymbolTable().getAllSymbols(True)}
 for entry,input_name,result_name,fastcall in [('nested_identity','choose_std','choose_std',False),('choose_std','target_fast','target_std',True)]:
  e=m.EmulatorHelper(m.program)
  try:
   preserved=[('EBP',0x11223344),('EBX',42),('ESI',0x12345678),('EDI',0x23456789)]
   for register,value in [('ESP',0x7fdc),('ECX',symbols[input_name]),*preserved]:e.writeRegister(register,BigInteger(str(value)))
   stack=(0x7ff0).to_bytes(4,'little')+(b''if fastcall else symbols[input_name].to_bytes(4,'little'))
   e.writeMemory(m.address(0x7fdc),JArray(JByte)(stack));e.setBreakpoint(m.address(0x7ff0))
   assert e.run(m.address(symbols[entry]),None,m.monitor),str(e.getLastError());assert e.getExecutionAddress()==m.address(0x7ff0)
   result=int(str(e.readRegister('EAX')))&0xffffffff;assert result==symbols[result_name]
   assert int(str(e.readRegister('ESP')))==0x7fe0
   for register,value in preserved:assert int(str(e.readRegister(register)))==value
   r['cases'].append({'entry':entry,'address':symbols[entry],'input_pointer_symbol':input_name,'input_pointer':symbols[input_name],'actual_input_storage':'ECX'if fastcall else'entryESP+4','source_convention':'__fastcall'if fastcall else'__cdecl','result_pointer_symbol':result_name,'result_pointer':result,'final_ESP':0x7fe0,'preserved_registers_checked':True})
  finally:e.dispose()
 r['completed']=True
except BaseException:r['failure']=traceback.format_exc()
finally:m.close();(a.out/'report.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'completed':r['completed'],'cases':len(r['cases']),'failure':r.get('failure')}))
if not r['completed']:raise SystemExit(1)
