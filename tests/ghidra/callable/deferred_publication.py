#!/usr/bin/env python3
"""Real deferred provider publication + unchanged emitted C, no helper-body fixes."""
import argparse,hashlib,json,re,struct,subprocess,traceback
from pathlib import Path
from support import tool
from whole_calls_workers import elf_symbols
p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--binary',type=Path,required=True);p.add_argument('--cli',type=Path,required=True);p.add_argument('--sha256',required=True);p.add_argument('--slot-address',type=lambda value:int(value,0),required=True);p.add_argument('--mode',choices=['all','serial','stream','jobs2'],default='all');p.add_argument('--case',choices=['all','scalar_formal_control','scalar_only','returned_callback_control','returned_scalar_callback','deferred_scalar_cycle'],default='all');a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False);repo=Path(__file__).resolve().parents[3];r={'completed':False,'selected_mode':a.mode,'selected_case':a.case,'cli_sha256':hashlib.sha256(a.cli.read_bytes()).hexdigest(),'binary_sha256':hashlib.sha256(a.binary.read_bytes()).hexdigest(),'cases':[]};assert r['cli_sha256']==a.sha256;symbols=elf_symbols(a.binary)
declarations=['typedef typedef int (*Fn)(int);','typedef typedef Fn (*Chooser)(void);','data '+hex(a.slot_address)+' Fn scalar_slot']
prototypes=['int actual_leaf(int value)','int scalar_child(Fn callback,int value)','int scalar_root(Fn callback,int value)','int scalar_only_child(int value)','int scalar_only_root(int value)','Fn actual_chooser(void)','Fn returned_child(Chooser chooser)','Fn returned_root(Chooser chooser)','int returned_consumer(Chooser chooser,int value)','int deferred_cycle_a(int depth,Fn callback)','int deferred_cycle_b(int depth,Fn callback)','int ordinary_cycle_a(int depth)','int ordinary_cycle_b(int depth)']
prototypes+=['Fn returned_scalar_child(int value)','Fn returned_scalar_root(int value)','int returned_scalar_consumer(int value)','int scalar_cycle_a(int depth)','int scalar_cycle_b(int depth)','int scalar_entry(int value)']
for declaration in prototypes:declarations+=['prototype '+declaration.split('(')[0].split()[-1]+' '+declaration]
assertions=['--assert-strict']
for declaration in declarations:assertions+=['--assert',declaration]
def authenticate_scalar_slot():
 image=a.binary.read_bytes();assert image[:6]==b'\x7fELF\x02\x01'
 shoff=struct.unpack_from('<Q',image,40)[0];entsize,count=struct.unpack_from('<HH',image,58)
 sections=[struct.unpack_from('<IIQQQQIIQQ',image,shoff+i*entsize)for i in range(count)]
 matches=[]
 for table in sections:
  if table[1]!=2:continue
  names_section=sections[table[6]];names=image[names_section[4]:names_section[4]+names_section[5]]
  for offset in range(table[4],table[4]+table[5],table[9]):
   name,info,_,section_index,address,size=struct.unpack_from('<IBBHQQ',image,offset)
   if names[name:names.index(0,name)]!=b'scalar_slot':continue
   assert info&15==1 and address==a.slot_address and size==8
   section=sections[section_index];assert section[1]==1 and section[2]&3==3
   relative=address-section[3];assert 0<=relative<=section[5]-8
   original=image[section[4]+relative:section[4]+relative+8]
   assert int.from_bytes(original,'little')==symbols['actual_leaf']
   matches.append({'address':address,'size':size,'original_bytes':original.hex(),'initializer_actual_leaf':symbols['actual_leaf'],'binary_sha256':r['binary_sha256']})
 assert len(matches)==1,matches
 return matches[0]
def dwarf_preflight():
 command=[tool('llvm-dwarfdump'),'--debug-info',str(a.binary.resolve())]
 result=subprocess.run(command,cwd=repo,capture_output=True,text=True,timeout=120)
 r['dwarf_preflight']={'command':command,'status':result.returncode,'stdout':result.stdout,'stderr':result.stderr,'binary_sha256':r['binary_sha256']}
 assert result.returncode==0,r['dwarf_preflight']
 blocks={}
 for match in re.finditer(r'(?m)^0x([0-9a-f]+):\s+(DW_TAG_\w+)',result.stdout):
  end=re.search(r'(?m)^0x[0-9a-f]+:',result.stdout[match.end():])
  body=result.stdout[match.end():match.end()+end.start()]if end else result.stdout[match.end():]
  blocks[int(match.group(1),16)]=(match.group(2),body)
 def named(tag,name):
  matches=[(address,body)for address,(kind,body)in blocks.items()if kind==tag and re.search(r'DW_AT_name\s+\("'+re.escape(name)+r'"\)',body)]
  assert matches,(tag,name)
  return matches
 def target(body):
  match=re.search(r'DW_AT_type\s+\(0x([0-9a-f]+)',body);assert match,body
  return int(match.group(1),16)
 slot=named('DW_TAG_variable','scalar_slot');assert len(slot)==1
 assert re.search(r'DW_OP_addr 0x0*'+format(a.slot_address,'x')+r'\)',slot[0][1]),slot
 volatile=target(slot[0][1]);assert blocks[volatile][0]=='DW_TAG_volatile_type'
 fn=target(blocks[volatile][1]);assert any(address==fn for address,_ in named('DW_TAG_typedef','Fn'))
 pointer=target(blocks[fn][1]);assert blocks[pointer][0]=='DW_TAG_pointer_type'
 callable_type=target(blocks[pointer][1]);assert blocks[callable_type][0]=='DW_TAG_subroutine_type'
 integer=target(blocks[callable_type][1]);assert blocks[integer][0]=='DW_TAG_base_type'and re.search(r'DW_AT_name\s+\("int"\)',blocks[integer][1])and re.search(r'DW_AT_byte_size\s+\(0x04\)',blocks[integer][1])
 callable_end=min(address for address in blocks if address>callable_type)
 assert blocks[callable_end][0]=='DW_TAG_formal_parameter'and target(blocks[callable_end][1])==integer
 for name in symbols:
  if name in [declaration.split('(')[0].split()[-1]for declaration in prototypes]:
   definitions=[body for _,body in named('DW_TAG_subprogram',name)if re.search(r'DW_AT_low_pc\s+\(0x0*'+format(symbols[name],'x')+r'\)',body)]
   assert definitions,(name,symbols[name])
 r['dwarf_preflight']['verified_source_graph']={'scalar_slot_address':a.slot_address,'scalar_slot_volatile':True,'Fn':'pointer to int(int)','source_subprograms':'Actual linked low_pc matches named prototypes, including separate-TU scalar_entry','same_machine_binary':True}
if a.mode!='serial':
 try:dwarf_preflight()
 except BaseException:
  r['failure']=traceback.format_exc();(a.out/'report.json').write_text(json.dumps(r,indent=2)+'\n');raise
cases=[
 ('scalar_formal_control',['scalar_entry','scalar_root','scalar_child','actual_leaf'],None,None),
 ('scalar_only',['scalar_only_root','scalar_only_child','actual_leaf'],'scalar_only_child','for(int x=-2;x<=31;++x)if(scalar_only_root(x)!=2*x+9)return 1;'),
 ('returned_callback_control',['returned_consumer','returned_root','returned_child','actual_chooser','actual_leaf'],None,'for(int x=-2;x<=31;++x){if(returned_root(actual_chooser)!=actual_leaf)return 1;if(returned_consumer(actual_chooser,x)!=2*x+1)return 2;}'),
 ('returned_scalar_callback',['returned_scalar_consumer','returned_scalar_root','returned_scalar_child','actual_leaf'],'returned_scalar_child','for(int x=-2;x<=31;++x){if(returned_scalar_root(x)!=actual_leaf)return 1;if(returned_scalar_consumer(x)!=2*x+1)return 2;}'),
 ('deferred_scalar_cycle',['scalar_cycle_a','scalar_cycle_b','actual_leaf'],'scalar_cycle_b','for(int depth=0;depth<=8;++depth){if(scalar_cycle_a(depth)!=11+depth)return 1;if(scalar_cycle_b(depth)!=11+depth)return 2;}'),
]
for mode in ['serial','stream','jobs2']:
 if a.mode!='all'and a.mode!=mode:continue
 for label,names,omitted,body in cases:
  if a.case!='all'and a.case!=label:continue
  out=a.out/(mode+'-'+label);out.mkdir();row={'mode':mode,'case':label,'completed':False,'commands':[],'source_type_provenance':'Existing accepted v4 genuine DWARF, no assertions or manual type replacement'if mode!='serial'else'Accepted serial source assertions over same genuine fixture','binary_sha256':r['binary_sha256']};r['cases'].append(row)
  def invoke(command):
   command=list(map(str,command));q=subprocess.run(command,cwd=repo,capture_output=True,text=True,timeout=240);v={'command':command,'status':q.returncode,'stdout':q.stdout,'stderr':q.stderr};row['commands'].append(v);return v
  try:
   jobs=['--jobs','2']if mode=='jobs2'else[];stream=['--stream']if mode=='stream'else[]
   for missing in ([True,False]if omitted else[False]):
    chosen=[name for name in names if not missing or name!=omitted];suffix='omitted'if missing else'full';common=['--functions',','.join(chosen),'--language','c','--option','structdefs','on',*jobs,*(assertions if mode=='serial'else[])]
    result=invoke([a.cli,'decompile-all',a.binary,'--json',*common]);assert result['status']==0,result;metadata=json.loads(result['stdout']);(out/(suffix+'-metadata.json')).write_text(json.dumps(metadata,indent=2)+'\n');assert len(metadata['functions'])==len(chosen)
    row.setdefault('actual_source_variables',{})[suffix]={f['name']:[{'name':v['name'],'type':v['type'],'size':v['size'],'arg_index':v['arg_index']}for v in f['variables']if v['kind']=='arg']for f in metadata['functions']}
    assert all(f.get('error')is None and f.get('code')and f.get('callable_export_error')is None for f in metadata['functions']),metadata
    artifacts=[artifact for f in metadata['functions']for artifact in f.get('callable_artifacts',[])]
    required=[artifact for artifact in artifacts if artifact.get('required')]
    project=out/(suffix+'-project');export=invoke([a.cli,'decompile-project',a.binary,'-o',project,*common,*stream])
    if missing:
     assert export['status']!=0,export
     # Streaming may leave partial files on refusal; none are consumed as a
     # completed unit. The exit status and missing exact owner are the contract.
     owned={artifact['key']for artifact in artifacts if artifact.get('definition')is not None};assert any(artifact['key']not in owned for artifact in required),artifacts
     row['omitted_provider_refused']=True;continue
    assert export['status']==0,export
    if omitted:
     requested={artifact['key']for artifact in required}
     owned=[artifact for f in metadata['functions']if f['address']==symbols[omitted]for artifact in f.get('callable_artifacts',[])if artifact['key']in requested and isinstance(artifact.get('definition'),dict)]
     assert any(artifact['definition'].get('kind')=='wrapper'or(artifact['definition'].get('kind')=='existing_target'and int(artifact['definition']['byte_address'],16)==symbols[omitted])for artifact in owned),{'expected_provider':omitted,'address':symbols[omitted],'owned_receipts':owned}
     row['deferred_provider_owner']={'function':omitted,'address':symbols[omitted],'receipts':owned}
    if label=='scalar_formal_control':
     body='for(int x=-2;x<=31;++x){if(scalar_entry(x)!=2*x+9)return 1;if(scalar_root(actual_leaf,x)!=2*x+9)return 2;}'
    stem=a.binary.name;driver=out/'consumer.c';driver.write_text('#include "'+stem+'.h"\nint main(void){'+body+'return 0;}\n')
    data_sources=[]
    if label in ['scalar_only','returned_scalar_callback','deferred_scalar_cycle']:
     header=(project/(stem+'.h')).read_text();declaration=re.search(r'(?m)^\s*extern\s+(volatile\s+)?Fn\s+(volatile\s+)?scalar_slot\s*;',header);assert declaration,header
     row['original_external_data']=authenticate_scalar_slot()
     actual_volatile=bool(declaration.group(1)or declaration.group(2));assert actual_volatile,header;row['actual_external_declaration']=declaration.group().strip()
     row['qualifier_projection_limit']='Original fixture storage is Fn volatile. Consumer matches actual public '+('volatile Fn; actual qualifier retained.'if actual_volatile else'Fn; no volatile qualifier projection claimed.')
     data=out/'fixture-data.c';data.write_text('#include "'+stem+'.h"\nFn '+('volatile 'if actual_volatile else'')+'scalar_slot=actual_leaf;\n');data_sources.append(data)
    row['emitted_sha256']={path.name:hashlib.sha256(path.read_bytes()).hexdigest()for path in [project/(stem+'.c'),project/(stem+'.h')]}
    for opt in ['-O0','-O2']:
     exe=out/('consumer'+opt);built=invoke(['cc','-std=c11','-Wall','-Wextra','-Werror=uninitialized','-Werror=incompatible-pointer-types','-Werror=implicit-function-declaration',opt,'-I',project,project/(stem+'.c'),driver,*data_sources,'-o',exe]);assert built['status']==0,built;ran=invoke([exe]);assert ran['status']==0,ran
    row['unchanged_C_passed']=True
   row['completed']=True
  except BaseException:row['failure']=traceback.format_exc()
  finally:(out/'report.json').write_text(json.dumps(row,indent=2)+'\n');print(json.dumps({'mode':mode,'case':label,'completed':row['completed'],'failure':row.get('failure')}),flush=True)
r['completed']=all(row['completed']for row in r['cases']);(a.out/'report.json').write_text(json.dumps(r,indent=2)+'\n')
if not r['completed']:raise SystemExit(1)
