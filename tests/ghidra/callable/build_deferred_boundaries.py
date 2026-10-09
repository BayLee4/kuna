#!/usr/bin/env python3
"""Compile genuine fixed-result/returned-callback/recursive provider bodies."""
import argparse,hashlib,json,subprocess
from pathlib import Path
from support import tool
p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False);source=Path(__file__).with_name('deferred_boundaries.c');consumer=Path(__file__).with_name('deferred_returned_consumers.c');obj=a.out/'deferred.o';consumer_obj=a.out/'consumers.o';binary=a.out/'deferred.elf';r={'completed':False,'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'consumer_source_sha256':hashlib.sha256(consumer.read_bytes()).hexdigest(),'commands':[]}
try:
 (a.out/'fixture-source.c').write_bytes(source.read_bytes())
 (a.out/'fixture-consumers.c').write_bytes(consumer.read_bytes())
 compiler=[tool('clang'),'--target=x86_64-unknown-linux-gnu','-O1','-gdwarf-4','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-optimize-sibling-calls','-fno-pic','-fno-pie']
 for command in [[*compiler,'-c',str(source),'-o',str(obj)],[*compiler,'-c',str(consumer),'-o',str(consumer_obj)],[tool('ld.lld'),'-m','elf_x86_64','--image-base=0','-Ttext=0x1000','-e','scalar_root','--build-id=none',str(obj),str(consumer_obj),'-o',str(binary)],[tool('llvm-objdump'),'-d',str(binary)],[tool('llvm-dwarfdump'),'--debug-info',str(binary)]]:
  q=subprocess.run(command,cwd='/tmp',capture_output=True,text=True,timeout=120);v={'command':command,'status':q.returncode,'stdout':q.stdout,'stderr':q.stderr};r['commands'].append(v);assert q.returncode==0,v
 r['binary_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest();r['completed']=True
finally:(a.out/'construction.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
