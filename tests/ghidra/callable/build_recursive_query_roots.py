#!/usr/bin/env python3
"""Build real identity functions solely to choose first live datatype query root."""
import argparse
import hashlib
import json
from pathlib import Path
from support import tool
import subprocess
parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,required=True);args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=False)
source=Path(__file__).with_name('recursive_query_roots.c');report={'source':str(source),'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'scope':'Genuine typed identity helpers for root-query ordering; never substituted as transform callback. Relocation-free function bytes imported through Ghidra object loader.','cases':[],'completed':False}
try:
 for name,target in [('x86','x86_64-unknown-linux-gnu'),('aarch64','aarch64-unknown-linux-gnu'),('apple','arm64-apple-macosx11.0')]:
  obj=args.out/(name+'.o');row={'target':name,'triple':target,'object':str(obj),'commands':[]};report['cases'].append(row)
  for command in [[tool('clang'),'--target='+target,'-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-c',str(source),'-o',str(obj)],[tool('llvm-objdump'),'-dr',str(obj)]]:
   p=subprocess.run(command,capture_output=True,text=True,timeout=120);value={'command':command,'status':p.returncode,'stdout':p.stdout,'stderr':p.stderr};row['commands'].append(value);assert p.returncode==0,value
  row['object_sha256']=hashlib.sha256(obj.read_bytes()).hexdigest()
 report['completed']=True
finally:(args.out/'construction.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
