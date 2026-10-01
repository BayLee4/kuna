#!/usr/bin/env python3
"""Original i386 stdcall/fastcall machine oracle; semantic roots are tested in Rust."""
import argparse,hashlib,json,os,subprocess,traceback
from pathlib import Path
from whole_calls_workers import ElfMachine
p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--binary',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False);binary=a.binary;r={'completed':False,'machine':[]}
try:
 r['binary_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest();m=ElfMachine(binary,a.out)
 try:
  from java.math import BigInteger
  from jpype import JArray,JByte
  assert str(m.program.getLanguageID())=='x86:LE:32:default'
  symbols={str(s.getName()):int(s.getAddress().getOffset())for s in m.program.getSymbolTable().getAllSymbols(True)}
  for entry,callee in [('call_old','old_callee'),('call_future','future_callee')]:
   for value in [0,1,37]:
    e=m.EmulatorHelper(m.program)
    try:
     for reg,v in [('ESP',0x7fc0),('EBP',0x11223344)]:e.writeRegister(reg,BigInteger(str(v)))
     data=b''.join(v.to_bytes(4,'little')for v in [0x7ff0,symbols[callee],value]);e.writeMemory(m.address(0x7fc0),JArray(JByte)(data));e.setBreakpoint(m.address(0x7ff0));assert e.run(m.address(symbols[entry]),None,m.monitor),str(e.getLastError())
     got=int(str(e.readRegister('EAX')));assert got==value+1 and int(str(e.readRegister('ESP')))==0x7fc4 and int(str(e.readRegister('EBP')))==0x11223344
     r['machine'].append({'entry':entry,'callee':callee,'input':value,'output':got,'final_ESP':0x7fc4})
    finally:e.dispose()
 finally:m.close()
 r['completed']=True
except BaseException:r['failure']=traceback.format_exc()
finally:(a.out/'report.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'completed':r['completed'],'failure':r.get('failure')}))
if not r['completed']:raise SystemExit(1)
