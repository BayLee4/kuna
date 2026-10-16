#!/usr/bin/env python3
"""Original-machine hidden boundary oracles and genuine callback provider C."""
import argparse,hashlib,json,subprocess,traceback
from pathlib import Path
from support import ROOT, tool, require_provider_body
from whole_calls_workers import ElfMachine,elf_symbols
p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--binary',type=Path,required=True);p.add_argument('--cli',type=Path,required=True);p.add_argument('--sha256',required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
repo=ROOT;r={'completed':False,'binary_sha256':hashlib.sha256(a.binary.read_bytes()).hexdigest(),'cli_sha256':hashlib.sha256(a.cli.read_bytes()).hexdigest(),'cases':[]};assert r['cli_sha256']==a.sha256
cases=[('hidden_local','make_big','BigFn',True),('hidden_overlap','make_big','BigFn',False),('hidden_below_sp','make_big','BigFn',False),('hidden_live_alias','make_big','BigFn',False),('hidden_explicit_alias','make_big_explicit','AliasFn',False),('hidden_raw_child','make_big','BigFn',False),('explicit_pointer','write_big','WriterFn',False)]
symbols=elf_symbols(a.binary);m=ElfMachine(a.binary,a.out)
try:
 from java.math import BigInteger
 assert str(m.program.getLanguageID())=='AARCH64:LE:64:v8A'
 for subject,callee,callback,positive in cases:
  row={'subject':subject,'callee':callee,'public_C_consumer':positive,'completed':False,'machine':[]};r['cases'].append(row);out=a.out/subject;out.mkdir()
  try:
   for tag in [0,5,19]:
    for entry in [subject]+(['outer_local']if subject=='hidden_local'else['outer_overlap']if subject=='hidden_overlap'else[]):
     e=m.EmulatorHelper(m.program)
     try:
      for reg,val in [('X0',symbols[callee]),('X1',tag),('X19',42),('X29',0x1122334455667788),('X30',0x7ff0),('sp',0x7fe0)]:e.writeRegister(reg,BigInteger(str(val)))
      e.setBreakpoint(m.address(0x7ff0));assert e.run(m.address(symbols[entry]),None,m.monitor),str(e.getLastError())
      value=int(str(e.readRegister('X0')));x19=int(str(e.readRegister('X19')))
      want=(42 if entry=='outer_local'else tag+3 if entry=='outer_overlap'else 2*tag+3 if subject in ['hidden_local','hidden_overlap','hidden_below_sp']else tag)
      assert value==want,(entry,tag,value,want)
      assert x19==(tag+3 if entry=='hidden_overlap'else 42),(entry,x19)
      assert int(str(e.readRegister('sp')))==0x7fe0 and int(str(e.readRegister('X29')))==0x1122334455667788
      row['machine'].append({'entry':entry,'tag':tag,'result':value,'final_X19':x19,'final_SP':0x7fe0})
     finally:e.dispose()
   declarations=['typedef typedef struct Big24 { unsigned long long a; unsigned long long b; unsigned long long c; } Big24;','typedef typedef Big24 (*BigFn)(int);','typedef typedef Big24 (*AliasFn)(int,Big24 *);','typedef typedef void (*WriterFn)(Big24 *,int);','prototype '+subject+' unsigned long long '+subject+'('+callback+' callback,int tag)','prototype make_big Big24 make_big(int tag)','prototype make_big_explicit Big24 make_big_explicit(int tag,Big24 *alias)','prototype write_big void write_big(Big24 *out,int tag)','prototype raw_child unsigned long long raw_child(void)']
   command=[str(a.cli),'decompile-all',str(a.binary),'--functions',subject,'--json','--language','c','--option','structdefs','on','--assert-strict']
   for declaration in declarations:command+=['--assert',declaration]
   q=subprocess.run(command,cwd=repo,capture_output=True,text=True,timeout=240);row['command']={'command':command,'status':q.returncode,'stdout':q.stdout,'stderr':q.stderr};assert q.returncode==0,row['command'];metadata=json.loads(q.stdout);(out/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n');assert len(metadata['functions'])==1 and {f['name']for f in metadata['functions']}=={subject};f=metadata['functions'][0];assert f.get('error')is None and f.get('code'),f
   if positive:
    # Consume the actual emitted provider, not a handwritten Big24 callback.
    common=['--functions',subject+','+callee,'--language','c','--option','structdefs','on','--assert-strict']
    for declaration in declarations:common+=['--assert',declaration]
    row['consumer_commands']=[]
    def invoke(command):
     command=list(map(str,command));result=subprocess.run(command,cwd=repo,capture_output=True,text=True,timeout=240)
     receipt={'command':command,'status':result.returncode,'stdout':result.stdout,'stderr':result.stderr};row['consumer_commands'].append(receipt);assert result.returncode==0,receipt
     return result.stdout
    full=json.loads(invoke([a.cli,'decompile-all',a.binary,'--json',*common]))
    (out/'provider-metadata.json').write_text(json.dumps(full,indent=2)+'\n')
    assert len(full['functions'])==2 and {f['name']for f in full['functions']}=={subject,callee},full
    assert all(f.get('error')is None and f.get('code')for f in full['functions']),full
    project=out/'project';invoke([a.cli,'decompile-project',a.binary,'-o',project,*common])
    for name in (subject,callee):require_provider_body(project/(a.binary.name+'.c'),name)
    stem=a.binary.name;driver=out/'consumer.c'
    driver.write_text('#include "'+stem+'.h"\nint main(void){for(int tag=-20;tag<=20;++tag){Big24 value=make_big(tag);if(value.a!=(unsigned long long)tag||value.b!=7||value.c!=(unsigned long long)(tag+3))return 1;if(hidden_local(make_big,tag)!=(unsigned long long)(2*tag+3))return 2;}return 0;}\n')
    row['emitted_sha256']={path.name:hashlib.sha256(path.read_bytes()).hexdigest()for path in [project/(stem+'.c'),project/(stem+'.h')]}
    for opt in ['-O0','-O2']:
     exe=out/('consumer'+opt);invoke([tool('cc'),'-std=c11','-Wall','-Wextra','-Werror=uninitialized','-Werror=incompatible-pointer-types','-Werror=implicit-function-declaration',opt,'-I',project,project/(stem+'.c'),driver,'-o',exe]);invoke([exe])
    row['emitted_provider_consumer']=True
   row['behavioral_checks_completed']=True
   row['completed']=True
  except BaseException:row['failure']=traceback.format_exc()
  finally:(out/'report.json').write_text(json.dumps(row,indent=2)+'\n');print(json.dumps({'subject':subject,'completed':row['completed'],'failure':row.get('failure')}),flush=True)
finally:m.close();r['completed']=all(x['completed']for x in r['cases']);(a.out/'report.json').write_text(json.dumps(r,indent=2)+'\n')
if not r['completed']:raise SystemExit(1)
