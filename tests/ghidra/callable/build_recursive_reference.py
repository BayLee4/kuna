#!/usr/bin/env python3
"""Compile the existing reviewed recursive Node/Fn source, without byte patches."""
import argparse
import hashlib
import json
from pathlib import Path
from support import tool
import subprocess

parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,required=True);args=parser.parse_args();args.out=args.out.resolve();args.out.mkdir(parents=True,exist_ok=False)
root=Path(__file__).resolve().parents[3]
source=Path(__file__).with_name('reference_abi.c')
report={'scope':'Fixture-only unchanged reviewed source compilation; no production build or decompiler output repair.','source':str(source),'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'cases':[],'completed':False}
try:
 for name,target,emulation in [('x86','x86_64-unknown-linux-gnu','elf_x86_64'),('aarch64','aarch64-unknown-linux-gnu','aarch64elf')]:
  obj=args.out/(name+'.o');binary=args.out/(name+'.elf');row={'target':target,'binary':str(binary),'commands':[]};report['cases'].append(row)
  commands=[[tool('clang'),'--target='+target,'-O1','-gdwarf-4','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-optimize-sibling-calls','-fno-pic','-fno-pie','-c',str(source),'-o',str(obj)],[tool('ld.lld'),'-m',emulation,'--image-base=0','-Ttext=0x1000','-e','drive','--build-id=none',str(obj),'-o',str(binary)],[tool('llvm-objdump'),'-d',str(binary)],[tool('llvm-dwarfdump'),'--debug-info',str(binary)]]
  for command in commands:
   p=subprocess.run(command,cwd='/tmp',capture_output=True,text=True,timeout=120);record={'command':command,'status':p.returncode,'stdout':p.stdout,'stderr':p.stderr};row['commands'].append(record);assert p.returncode==0,record
  row['elf_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest()
 apple=args.out/'production-smoke'
 # Apple query-order cases deliberately create their authoritative graph via
 # assertions; the ELF fixtures above retain genuine DWARF as separate controls.
 command=[tool('clang'),'--target=arm64-apple-macosx11.0','-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-c',str(source),'-o',str(apple)]
 result=subprocess.run(command,capture_output=True,text=True,timeout=120)
 report['apple']={'command':command,'status':result.returncode,'stdout':result.stdout,'stderr':result.stderr}
 assert result.returncode==0,report['apple']
 report['completed']=True
finally:
 (args.out/'construction.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
