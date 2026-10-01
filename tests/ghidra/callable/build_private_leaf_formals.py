#!/usr/bin/env python3
"""Reuse the reviewed ELF/DWARF donor construction for an unchanged-ABI leaf."""
import argparse
import json
from pathlib import Path
from support import ROOT, tool
import subprocess
from build_whole_calls_formals import sha,symbols_and_sections
from whole_calls import rel

parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
args.out.mkdir(parents=True,exist_ok=False)
source=(Path(__file__).parent/'fixtures'/'private_leaf_formals.c').resolve()
obj=args.out/'private_leaf_formals.o';donor=args.out/'private_leaf_formals.donor.elf';binary=args.out/'private_leaf_formals.elf'
commands=[[tool('clang'),'--target=x86_64-unknown-linux-gnu','-O2','-gdwarf-4','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pic','-fno-pie','-c',str(source),'-o',str(obj)],[tool('ld.lld'),'-m','elf_x86_64','--image-base=0','-Ttext=0x1000','-e','dispatch','--build-id=none',str(obj),'-o',str(donor)]]
report={'source_sha256':sha(source.read_bytes()),'builder_sha256':sha(Path(__file__).read_bytes()),'commands':[]}
for command in commands:
 p=subprocess.run(command,capture_output=True,text=True);row={'command':command,'status':p.returncode,'stdout':p.stdout,'stderr':p.stderr};report['commands'].append(row);assert p.returncode==0,row
original=donor.read_bytes();symbols,sections=symbols_and_sections(original)
assert set(symbols)=={'dispatch','subject'},symbols
prefix=bytes.fromhex('55bd2a000000')
bodies={'subject':bytes.fromhex('5548c707070000005dc3'),'dispatch':prefix+rel(0xe8,symbols['dispatch']['address']+len(prefix),symbols['subject']['address'])+bytes.fromhex('4889e85dc3')}
patched=bytearray(original);rows=[]
for name,body in bodies.items():
 symbol=symbols[name];offset,size=symbol['offset'],symbol['size']
 assert len(body)<=64<=size and bytes([0x90])*64 in original[offset:offset+size],symbol
 assert symbol['address']+size<0x6000,'code overlaps original-machine disjoint data'
 patched[offset:offset+len(body)]=body
 rows.append({'name':name,**symbol,'machine_bytes':body.hex(),'replaced_bytes':original[offset:offset+len(body)].hex()})
for name,section in sections.items():
 if name.startswith('.debug_'):
  start,size=section[4],section[5];assert original[start:start+size]==patched[start:start+size],name
binary.write_bytes(patched)
report.update({'donor_sha256':sha(original),'elf_sha256':sha(patched),'binary':str(binary),'functions':rows,'debug_sections_byte_identical':True,'limits':'Authentic entry declaration DIEs only; donor post-entry location lists are not an execution-debug oracle. Original-machine and unchanged generated-C validation remain independent.'})
(args.out/'construction.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
