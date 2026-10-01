#!/usr/bin/env python3
"""Compile real AArch64 static/branch-merged BLR result providers."""
import argparse,hashlib,json,subprocess
from pathlib import Path
from support import tool
p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out=a.out.resolve();a.out.mkdir(parents=True,exist_ok=False);source=Path(__file__).with_name('finite_big_results.s');obj=a.out/'finite-big.o';binary=a.out/'finite-big.elf';r={'completed':False,'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'commands':[]};(a.out/'fixture-source.s').write_bytes(source.read_bytes())
try:
 for command in [[tool('clang'),'--target=aarch64-unknown-linux-gnu','-c',str(source),'-o',str(obj)],[tool('ld.lld'),'-m','aarch64elf','--image-base=0','-Ttext=0x1000','-e','finite_static','--build-id=none',str(obj),'-o',str(binary)],[tool('llvm-objdump'),'-d','-t',str(binary)]]:
  q=subprocess.run(command,cwd='/tmp',capture_output=True,text=True,timeout=120);result={'command':command,'status':q.returncode,'stdout':q.stdout,'stderr':q.stderr};r['commands'].append(result);assert q.returncode==0,result
 r['binary_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest();r['completed']=True
finally:(a.out/'construction.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
