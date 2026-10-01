#!/usr/bin/env python3
"""Historical Apple conversion record replay from exact embedded Mach-O bytes.

Not part of the active aggregator: the original source/builder is missing.
This replay retains the actual machine and emitted-provider consumer requirements.
"""
import argparse,base64,hashlib,json,subprocess,traceback,zlib
from pathlib import Path
from support import ROOT, tool
from whole_calls_workers import ElfMachine
p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--cli',type=Path,required=True);p.add_argument('--sha256',required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
repo=ROOT;record=json.loads((Path(__file__).parent/'fixtures/hidden_result_apple_record.json').read_text());binary=a.out/'production-smoke'
original=zlib.decompress(base64.b64decode(record['binary_zlib_base64']));assert len(original)==record['binary_size'] and hashlib.sha256(original).hexdigest()==record['binary_sha256'];binary.write_bytes(original)
r={'completed':False,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'cli_sha256':hashlib.sha256(a.cli.read_bytes()).hexdigest(),'machine':[],'commands':[]};assert r['cli_sha256']==a.sha256
try:
 m=ElfMachine(binary,a.out)
 try:
  from jpype import JArray,JByte
  from java.math import BigInteger
  assert str(m.program.getLanguageID())=='AARCH64:LE:64:AppleSilicon'
  for tag in range(-20,21):
   e=m.EmulatorHelper(m.program)
   try:
    for reg,val in [('X0',0x1000004c0),('X1',tag&0xffffffff),('X29',0x1122334455667788),('X30',0x7ff0),('sp',0x7fe0)]:e.writeRegister(reg,BigInteger(str(val)))
    e.setBreakpoint(m.address(0x1000004a4));assert e.run(m.address(0x10000048c),None,m.monitor),str(e.getLastError())
    call_sp=int(str(e.readRegister('sp')));hidden=int(str(e.readRegister('X8')));assert call_sp==0x7fb0 and hidden==call_sp+8
    assert hidden+24==call_sp+32 # disjoint from saved X29/X30 beginning +32
    e.clearBreakpoint(m.address(0x1000004a4));e.setBreakpoint(m.address(0x7ff0));assert e.run(m.monitor),str(e.getLastError())
    got=int(str(e.readRegister('X0')))&((1<<64)-1);want=(2*tag+3)&((1<<64)-1);assert got==want,(tag,got,want)
    assert int(str(e.readRegister('sp')))==0x7fe0 and int(str(e.readRegister('X29')))==0x1122334455667788
    result=bytes(int(x)&255 for x in e.readMemory(m.address(hidden),24));words=[int.from_bytes(result[i:i+8],'little')for i in [0,8,16]];assert words==[tag&((1<<64)-1),7,(tag+3)&((1<<64)-1)]
    r['machine'].append({'tag':tag,'result':got,'call_SP':call_sp,'hidden_X8':hidden,'result_words':words,'final_SP':0x7fe0,'restored_X29':True})
   finally:e.dispose()
 finally:m.close()
 def run(cmd):
  cmd=list(map(str,cmd));q=subprocess.run(cmd,cwd=repo,capture_output=True,text=True,timeout=240);v={'command':cmd,'status':q.returncode,'stdout':q.stdout,'stderr':q.stderr};r['commands'].append(v);return v
 common=['--functions','drive_big,make_big','--language','c','--option','structdefs','on','--assert','typedef typedef struct Big24 { unsigned long long a; unsigned long long b; unsigned long long c; } Big24;','--assert','typedef typedef Big24 (*BigFn)(int);','--assert','prototype drive_big unsigned long long drive_big(BigFn callback,int tag)','--assert','prototype make_big Big24 make_big(int tag)','--assert-strict']
 meta=run([a.cli,'decompile-all',binary,'--json',*common]);assert meta['status']==0,meta
 metadata=json.loads(meta['stdout']);(a.out/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n');assert len(metadata['functions'])==2
 assert all(f.get('error')is None and f.get('code')and f.get('callable_export_error')is None for f in metadata['functions']),metadata
 project=a.out/'project';export=run([a.cli,'decompile-project',binary,'-o',project,*common]);assert export['status']==0,export
 driver=a.out/'consumer.c';driver.write_text('#include "production-smoke.h"\nint main(void){for(int tag=-20;tag<=20;++tag){Big24 r=_make_big(tag);if(r.a!=(unsigned long long)tag||r.b!=7||r.c!=(unsigned long long)(tag+3))return 1;if(_drive_big(_make_big,tag)!=(unsigned long long)(2*tag+3))return 2;}return 0;}\n')
 r['emitted_sha256']={x.name:hashlib.sha256(x.read_bytes()).hexdigest()for x in [project/'production-smoke.c',project/'production-smoke.h']}
 for opt in ['-O0','-O2']:
  exe=a.out/('consumer'+opt);v=run([tool('cc'),'-std=c11','-Wall','-Wextra','-Werror=uninitialized','-Werror=incompatible-pointer-types','-Werror=implicit-function-declaration',opt,'-I',project,project/'production-smoke.c',driver,'-o',exe]);assert v['status']==0,v;v=run([exe]);assert v['status']==0,v
 r['completed']=True
except BaseException:r['failure']=traceback.format_exc()
finally:(a.out/'report.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'completed':r['completed'],'failure':r.get('failure')}))
if not r['completed']:raise SystemExit(1)
