#!/usr/bin/env python3
"""Genuine x86-32 direct callees: observed incoming stack/ECX and RET pop."""
import argparse,hashlib,json,traceback
from pathlib import Path
from whole_calls_workers import ElfMachine
p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False);r={'completed':False,'binary_sha256':hashlib.sha256(a.binary.read_bytes()).hexdigest(),'source_abi':'Hand-assembled __cdecl caller, actual __stdcall stack/RET4 or MS __fastcall ECX/RET target. x86 decoder independent of import compiler; no prototype-based emulation.','cases':[]};m=ElfMachine(a.binary,a.out)
try:
 from jpype import JArray,JByte
 from java.math import BigInteger
 assert str(m.program.getLanguageID())=='x86:LE:32:default';symbols={str(s.getName()):int(s.getAddress().getOffset())for s in m.program.getSymbolTable().getAllSymbols(True)}
 for caller,target,convention in [('caller_std','target_std','__stdcall'),('caller_fast','target_fast','__fastcall')]:
  for value in [-11,-3,0,9,100]:
   e=m.EmulatorHelper(m.program)
   try:
    preserved=[('EBP',0x11223344),('EBX',42),('ESI',0x12345678),('EDI',0x23456789)]
    for register,initial in [('ESP',0x7fdc),*preserved]:e.writeRegister(register,BigInteger(str(initial)))
    e.writeMemory(m.address(0x7fdc),JArray(JByte)((0x7ff0).to_bytes(4,'little')+(value&0xffffffff).to_bytes(4,'little')))
    e.setBreakpoint(m.address(symbols[target]));assert e.run(m.address(symbols[caller]),None,m.monitor),str(e.getLastError());assert e.getExecutionAddress()==m.address(symbols[target]);callee_sp=int(str(e.readRegister('ESP')))
    raw=(bytes(int(x)&255 for x in e.readMemory(m.address(callee_sp+4),4))if convention=='__stdcall'else(int(str(e.readRegister('ECX')))&0xffffffff).to_bytes(4,'little'));assert int.from_bytes(raw,'little',signed=True)==value
    return_pc=int.from_bytes(bytes(int(x)&255 for x in e.readMemory(m.address(callee_sp),4)),'little');e.clearBreakpoint(m.address(symbols[target]));e.setBreakpoint(m.address(return_pc));assert e.run(m.monitor),str(e.getLastError());assert e.getExecutionAddress()==m.address(return_pc);callee_after=int(str(e.readRegister('ESP')));assert callee_after-callee_sp==(8 if convention=='__stdcall'else 4)
    e.clearBreakpoint(m.address(return_pc));e.setBreakpoint(m.address(0x7ff0));assert e.run(m.monitor),str(e.getLastError());assert e.getExecutionAddress()==m.address(0x7ff0);result=int.from_bytes((int(str(e.readRegister('EAX')))&0xffffffff).to_bytes(4,'little'),'little',signed=True);assert result==value+7 and int(str(e.readRegister('ESP')))==0x7fe0
    for register,initial in preserved:assert int(str(e.readRegister(register)))==initial
    r['cases'].append({'caller':caller,'target':target,'model':convention,'value':value,'result':result,'actual_input':'stack+4'if convention=='__stdcall'else'ECX','callee_entry_ESP':callee_sp,'callee_ret_pop':callee_after-callee_sp,'final_ESP':0x7fe0})
   finally:e.dispose()
 r['completed']=True
except BaseException:r['failure']=traceback.format_exc()
finally:m.close();(a.out/'report.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'completed':r['completed'],'cases':len(r['cases']),'failure':r.get('failure')}))
if not r['completed']:raise SystemExit(1)
