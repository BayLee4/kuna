#!/usr/bin/env python3
"""Compile actual AArch64 hidden-result boundary fixture; no production build."""
import argparse,hashlib,json,subprocess
from pathlib import Path
from support import ROOT, tool
p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False);source=(Path(__file__).parent/'fixtures'/'hidden_boundaries.s');obj=a.out/'hidden.o';binary=a.out/'hidden.elf';r={'completed':False,'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'commands':[]}
try:
 for cmd in [[tool('clang'),'--target=aarch64-unknown-linux-gnu','-c',str(source),'-o',str(obj)],[tool('ld.lld'),'-m','aarch64elf','--image-base=0','-Ttext=0x1000','-e','hidden_local','--build-id=none',str(obj),'-o',str(binary)],[tool('llvm-objdump'),'-d',str(binary)]]:
  p=subprocess.run(cmd,cwd='/tmp',capture_output=True,text=True,timeout=120);v={'command':cmd,'status':p.returncode,'stdout':p.stdout,'stderr':p.stderr};r['commands'].append(v);assert p.returncode==0,v
 r['binary_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest();r['completed']=True
finally:(a.out/'construction.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
