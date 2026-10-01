#!/usr/bin/env python3
import argparse,hashlib,json,subprocess
from pathlib import Path
from support import tool
p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False);source=Path(__file__).with_name('nondefault_direct.S');obj=a.out/'conventions.o';binary=a.out/'conventions.elf';r={'completed':False,'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'commands':[]};(a.out/'fixture-source.S').write_bytes(source.read_bytes())
try:
 for command in [[tool('clang'),'--target=i386-unknown-linux-gnu','-c',str(source),'-o',str(obj)],[tool('ld.lld'),'-m','elf_i386','--image-base=0','-Ttext=0x1000','-e','caller_std','--build-id=none',str(obj),'-o',str(binary)],[tool('llvm-objdump'),'-d',str(binary)]]:
  q=subprocess.run(command,cwd='/tmp',capture_output=True,text=True,timeout=120);v={'command':command,'status':q.returncode,'stdout':q.stdout,'stderr':q.stderr};r['commands'].append(v);assert q.returncode==0,v
 r['binary_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest();r['completed']=True
finally:(a.out/'construction.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
