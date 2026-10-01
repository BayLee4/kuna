#!/usr/bin/env python3
"""Candidate raw-vs-selected demand oracle; internal divergence needs separate receipt."""
import argparse,hashlib,json,subprocess,traceback
from pathlib import Path
from support import ROOT, tool
from whole_calls_workers import ElfMachine,elf_symbols
p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--binary',type=Path,required=True);p.add_argument('--cli',type=Path);p.add_argument('--sha256');p.add_argument('--phase',choices=['machine','all'],default='all');a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False);repo=ROOT;r={'completed':False,'phase':a.phase,'scope':'Actual machine and admission only; no claim selected-vs-raw map divergence without separate internal evidence','machine':[],'commands':[],'binary_sha256':hashlib.sha256(a.binary.read_bytes()).hexdigest()}
if a.phase=='all':r['cli_sha256']=hashlib.sha256(a.cli.read_bytes()).hexdigest();assert r['cli_sha256']==a.sha256
try:
 symbols=elf_symbols(a.binary);m=ElfMachine(a.binary,a.out)
 try:
  from java.math import BigInteger
  data_symbols={str(s.getName()):int(s.getAddress().getOffset())for s in m.program.getSymbolTable().getAllSymbols(True)}
  for entry in ['hidden_selected_child','selected_child']:
   e=m.EmulatorHelper(m.program)
   try:
    for register,value in [('X0',symbols['make_big_zero']if entry=='hidden_selected_child'else 0x76543210),('X19',42),('X29',0x1122334455667788),('X30',0x7ff0),('sp',0x7fe0)]:e.writeRegister(register,BigInteger(str(value)))
    e.setBreakpoint(m.address(0x7ff0));assert e.run(m.address(symbols[entry]),None,m.monitor),str(e.getLastError());got=int(str(e.readRegister('X0')));assert got==13
    assert int(str(e.readRegister('sp')))==0x7fe0 and int(str(e.readRegister('X19')))==42 and int(str(e.readRegister('X29')))==0x1122334455667788
    r['machine'].append({'entry':entry,'result':got,'final_SP':0x7fe0,'final_X19':42})
   finally:e.dispose()
 finally:m.close()
 if a.phase=='all':
  declarations=['typedef typedef struct Big24 { unsigned long long a; unsigned long long b; unsigned long long c; } Big24;','typedef typedef Big24 (*Big0Fn)(void);','typedef typedef unsigned long long *(*PtrFn)(void);','prototype hidden_selected_child unsigned long long hidden_selected_child(Big0Fn callback)','prototype make_big_zero Big24 make_big_zero(void)','prototype selected_child unsigned long long selected_child(void)','prototype native_pointer unsigned long long *native_pointer(void)','data '+hex(data_symbols['pointer_slot'])+' PtrFn pointer_slot','data '+hex(data_symbols['pointer_value'])+' unsigned long long pointer_value']
  command=[str(a.cli),'decompile-all',str(a.binary),'--functions','hidden_selected_child,selected_child','--json','--language','c','--option','structdefs','on','--assert-strict']
  for d in declarations:command+=['--assert',d]
  q=subprocess.run(command,cwd=repo,capture_output=True,text=True,timeout=240);r['commands'].append({'command':command,'status':q.returncode,'stdout':q.stdout,'stderr':q.stderr});assert q.returncode==0;meta=json.loads(q.stdout);(a.out/'metadata.json').write_text(json.dumps(meta,indent=2)+'\n');functions={f['name']:f for f in meta['functions']};assert set(functions)=={'hidden_selected_child','selected_child'}
  for f in functions.values():assert f.get('error')is None and f.get('code'),f
  assert functions['hidden_selected_child'].get('callable_export_error')is not None,functions['hidden_selected_child']
  r['parent_refused']=True;r['child_admitted']=functions['selected_child'].get('callable_export_error')is None
 r['completed']=True
except BaseException:r['failure']=traceback.format_exc()
finally:(a.out/'report.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'completed':r['completed'],'child_admitted':r.get('child_admitted'),'failure':r.get('failure')}))
if not r['completed']:raise SystemExit(1)
