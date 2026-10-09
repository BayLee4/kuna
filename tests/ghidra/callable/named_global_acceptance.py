#!/usr/bin/env python3
"""Authentic named whole-object and address-taking exports with globalref on/off."""
import argparse,hashlib,json,re,subprocess,traceback
from pathlib import Path
from support import ROOT, tool, require_provider_body
from whole_calls_workers import ElfMachine,elf_symbols
p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--binary',type=Path,required=True);p.add_argument('--cli',type=Path);p.add_argument('--sha256');p.add_argument('--phase',choices=['machine','export','all'],default='all');p.add_argument('--state-address',type=lambda value:int(value,0),required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False);repo=ROOT;r={'completed':False,'phase':a.phase,'binary_sha256':hashlib.sha256(a.binary.read_bytes()).hexdigest(),'machine':[],'cases':[]}
if a.phase!='machine':r['cli_sha256']=hashlib.sha256(a.cli.read_bytes()).hexdigest();assert r['cli_sha256']==a.sha256
try:
 if a.phase!='export':
  m=ElfMachine(a.binary,a.out);symbols=elf_symbols(a.binary)
  try:
   from java.math import BigInteger
   from jpype import JArray,JByte
   state_symbols=[symbol for symbol in m.program.getSymbolTable().getAllSymbols(True)if str(symbol.getName())=='state'];assert len(state_symbols)==1
   state_address=state_symbols[0].getAddress();assert int(state_address.getOffset())==a.state_address
   initial=JArray(JByte)(16);assert m.program.getMemory().getBytes(state_address,initial)==16
   initial_bytes=bytes(int(value)&255 for value in initial);assert initial_bytes==(17).to_bytes(8,'little')+(3).to_bytes(4,'little')+bytes(4)
   r['original_state']={'address':a.state_address,'bytes':initial_bytes.hex(),'count':17,'delta':3,'reserved':0}
   changed_bytes=(100).to_bytes(8,'little')+(-7).to_bytes(4,'little',signed=True)+bytes(4)
   for entry,wanted,state_bytes in [('read_state',20,initial_bytes),('read_state',93,changed_bytes),('state_address',a.state_address,initial_bytes)]:
    e=m.EmulatorHelper(m.program)
    try:
     e.writeMemory(state_address,JArray(JByte)(state_bytes))
     e.writeRegister('RSP',BigInteger(str(0x7fd8)));e.writeMemory(m.address(0x7fd8),JArray(JByte)((0x7ff0).to_bytes(8,'little')));e.setBreakpoint(m.address(0x7ff0));assert e.run(m.address(symbols[entry]),None,m.monitor),str(e.getLastError());assert e.getExecutionAddress()==m.address(0x7ff0);got=int(str(e.readRegister('RAX')));assert got==wanted and int(str(e.readRegister('RSP')))==0x7fe0
     r['machine'].append({'entry':entry,'state_bytes':state_bytes.hex(),'result':got,'final_RSP':0x7fe0})
    finally:e.dispose()
  finally:m.close()
 if a.phase!='machine':
  # The genuine -gdwarf-4 image already imports the complete nominal State.
  # Re-declaring its body would correctly violate transactional publication.
  declarations=['data '+hex(a.state_address)+' State state','prototype read_state unsigned long long read_state(void)','prototype state_address State *state_address(void)']
  r['type_provenance']='Actual fixture DWARF State; no duplicate typedef/body assertion. Consumer checks exact size/field offsets and sizes.'
  assertions=['--assert-strict']
  for declaration in declarations:assertions+=['--assert',declaration]
  for globalref in ['on','off']:
   for fn,body in [('read_state','if(read_state()!=20)return 1;state.count=100;state.delta=-7;if(read_state()!=93)return 2;'),('state_address','if(state_address()!=&state)return 1;')]:
    out=a.out/(globalref+'-'+fn);out.mkdir();row={'globalref':globalref,'function':fn,'completed':False,'commands':[]};r['cases'].append(row)
    def invoke(command):
     command=list(map(str,command));q=subprocess.run(command,cwd=repo,capture_output=True,text=True,timeout=240);v={'command':command,'status':q.returncode,'stdout':q.stdout,'stderr':q.stderr};row['commands'].append(v);return v
    try:
     common=['--functions',fn,'--language','c','--option','structdefs','on','--option','globalref',globalref,*assertions];meta=invoke([a.cli,'decompile-all',a.binary,'--json',*common]);assert meta['status']==0,meta;metadata=json.loads(meta['stdout']);(out/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n');assert [f['name']for f in metadata['functions']]==[fn],metadata
     project=out/'project';export=invoke([a.cli,'decompile-project',a.binary,'-o',project,*common]);assert export['status']==0,export
     stem=a.binary.name;header=project/(stem+'.h');text=header.read_text();assert re.search(r'\bextern\s+(?:struct\s+)?State\s+state\s*;',text),text
     require_provider_body(project/(stem+'.c'),fn)
     # Only after the genuine public extern exists: original concrete data, not a missing declaration/body repair.
     driver=out/'consumer.c';driver.write_text('#include "'+stem+'.h"\n#include <stddef.h>\n_Static_assert(sizeof(State)==16,"original State size");\n_Static_assert(offsetof(State,count)==0 && sizeof(((State *)0)->count)==8,"original count layout");\n_Static_assert(offsetof(State,delta)==8 && sizeof(((State *)0)->delta)==4,"original delta layout");\n_Static_assert(offsetof(State,reserved)==12 && sizeof(((State *)0)->reserved)==4,"original reserved layout");\nState state={17,3,0};\nint main(void){'+body+'return 0;}\n')
     row['emitted_sha256']={path.name:hashlib.sha256(path.read_bytes()).hexdigest()for path in [project/(stem+'.c'),header]}
     for opt in ['-O0','-O2']:
      exe=out/('consumer'+opt);built=invoke([tool('cc'),'-std=c11','-Wall','-Wextra','-Werror=uninitialized','-Werror=incompatible-pointer-types','-Werror=implicit-function-declaration',opt,'-I',project,project/(stem+'.c'),driver,'-o',exe]);assert built['status']==0,built;ran=invoke([exe]);assert ran['status']==0,ran
     row['completed']=True
    except BaseException:row['failure']=traceback.format_exc()
    finally:(out/'report.json').write_text(json.dumps(row,indent=2)+'\n');print(json.dumps({'globalref':globalref,'function':fn,'completed':row['completed'],'failure':row.get('failure')}),flush=True)
 r['completed']=all(row['completed']for row in r['cases'])
except BaseException:r['failure']=traceback.format_exc()
finally:(a.out/'report.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'completed':r['completed'],'failure':r.get('failure')}))
if not r['completed']:raise SystemExit(1)
