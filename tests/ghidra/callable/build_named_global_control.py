#!/usr/bin/env python3
import argparse,hashlib,json,subprocess
from pathlib import Path
from support import ROOT, tool
p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False);source=(Path(__file__).parent/'fixtures'/'named_global_control.c');obj=a.out/'named.o';binary=a.out/'named.elf';r={'completed':False,'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'commands':[]};(a.out/'fixture-source.c').write_bytes(source.read_bytes())
try:
 for cmd in [[tool('clang'),'--target=x86_64-unknown-linux-gnu','-O1','-gdwarf-4','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-optimize-sibling-calls','-fno-pic','-fno-pie','-c',str(source),'-o',str(obj)],[tool('ld.lld'),'-m','elf_x86_64','--image-base=0','-Ttext=0x1000','-e','read_state','--build-id=none',str(obj),'-o',str(binary)],[tool('llvm-objdump'),'-dr',str(binary)],[tool('llvm-readelf'),'-s',str(binary)]]:
  q=subprocess.run(cmd,cwd='/tmp',capture_output=True,text=True,timeout=120);v={'command':cmd,'status':q.returncode,'stdout':q.stdout,'stderr':q.stderr};r['commands'].append(v);assert q.returncode==0,v
 r['binary_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest();r['completed']=True
finally:(a.out/'construction.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
