#!/usr/bin/env python3
"""Observe real saved-RBP alias effects through an ABI-preserving outer caller."""
import argparse
import hashlib
import json
from pathlib import Path
from support import ROOT, cli as default_cli, output, tool, start_ghidra, require_provider_body
import subprocess
import traceback
from whole_calls import Machine

parser=argparse.ArgumentParser()
parser.add_argument('--cli',type=Path)
parser.add_argument('--out',type=Path)
parser.add_argument('--machine-only',action='store_true')
parser.add_argument('--case',default='all',choices=('all','branch_alias','partial_saved_pointer','partial_pointer_write','callee_partial_pointer_write','passed_frame','callback_frame','delayed_frame_escape','disjoint_store'))
args=parser.parse_args()
args.cli = args.cli.resolve() if args.cli else None if args.machine_only else default_cli()
args.out = (args.out or output("private_frame_aliases")/"run").resolve()
args.out.mkdir(parents=True,exist_ok=False)
root=ROOT
report={'scope':'Original machine and source/project controls; disjoint-store C is mandatory, physical-frame C is investigation-only.','machine_only':args.machine_only,'completed':False,'cli_sha256':None if args.cli is None else hashlib.sha256(args.cli.read_bytes()).hexdigest(),'cases':[]}
outer='55bd2a000000e8f50000004889e85dc3'
cases=[
 {'name':'branch_alias','outer':outer,'subject':'554883ec0885ff7406488d0424eb05488d44240848c700000000004883c4085dc3','params':'choice','vectors':[(0,0),(1,42),(0xffffffff,42)],'allow_boundary':True,
  'driver':'if(dispatch(0)!=0 || dispatch(1)!=42 || dispatch(UINT32_MAX)!=42) return 1;'},
 {'name':'partial_saved_pointer','outer':outer,'subject':'554883ec10488d442410488904248b042448c700000000004883c4105dc3','params':'none','vectors':[(0,0)],'allow_boundary':True,
  'driver':'if(dispatch()!=0) return 2;'},
 {'name':'partial_pointer_write','outer':outer,'subject':'55488d042424f848c700000000005dc3','params':'none','vectors':[(0,0)],'allow_boundary':True,
  'driver':'if(dispatch()!=0) return 3;'},
 {'name':'callee_partial_pointer_write','outer':outer,'subject':'55488d0424e8f600000048c700000000005dc3','writer':'b0c8c3','byte_child':True,'params':'none','vectors':[(0,0)],'allow_boundary':True,
  'driver':'if(dispatch()!=0) return 9;'},
 {'name':'passed_frame','outer':outer,'subject':'554889e7e8f70000005dc3','writer':'48c70700000000c3','params':'none','vectors':[(0,0)],'allow_boundary':True,
  'driver':'if(dispatch()!=0) return 4;'},
 {'name':'callback_frame','outer':'55bd2a000000488d3df3010000e8ee0000004889e85dc3','subject':'554889f84889e731f6ffd05dc3','writer':'48c70700000000c3','params':'callback','vectors':[(0,0)],'allow_boundary':True,
  'driver':'if(dispatch()!=0) return 5;'},
 {'name':'delayed_frame_escape','outer':'55bd2a000000488d3df3010000e8ee0000004889e85dc3','subject':'4889f8488d7c24f831f6ffd055488b05ec1e000048c700000000005dc3','writer':'48893df91d0000c3','params':'callback','vectors':[(0,0)],'allow_boundary':True,'escaped_global':True,
  'driver':'if(dispatch()!=0) return 8;'},
 {'name':'disjoint_store','outer':outer,'subject':'5548c707070000005dc3','params':'pointer','vectors':[(0x6000,42)],'allow_boundary':False,
  'driver':'void *slot=calloc(1,8); if(!slot)return 6; uint64_t got=dispatch(slot),stored=0; memcpy(&stored,slot,8);free(slot); if(got!=42 || stored!=7)return 7;'},
]

def machine_case(case,row):
    from jpype import JArray,JByte
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.data import (VoidDataType,UnsignedIntegerDataType,UnsignedCharDataType,UnsignedLongLongDataType,PointerDataType,FunctionDefinitionDataType,ParameterDefinition,ParameterDefinitionImpl)
    from ghidra.program.model.listing import Function,ParameterImpl,ReturnParameterImpl,Variable
    from ghidra.program.model.symbol import SourceType
    void=VoidDataType.dataType;uint=UnsignedIntegerDataType.dataType;byte=UnsignedCharDataType.dataType;wide=UnsignedLongLongDataType.dataType
    entries=[('dispatch',0x1000,bytes.fromhex(case['outer']),''),('subject',0x1100,bytes.fromhex(case['subject']),'')]
    if 'writer'in case:entries.append(('child'if case.get('byte_child')else'writer',0x1200,bytes.fromhex(case['writer']),''))
    image=bytearray(0x2010 if case.get('escaped_global') else 0x210)
    for _,address,code,_ in entries:image[address-0x1000:address-0x1000+len(code)]=code
    machine=Machine(image,entries)
    try:
        api=FlatProgramAPI(machine.program,machine.monitor)
        pointer=PointerDataType(wide,machine.program.getDataTypeManager())
        definition=FunctionDefinitionDataType('Writer',machine.program.getDataTypeManager());definition.setCallingConvention('__stdcall');definition.setReturnType(void)
        definition.setArguments(JArray(ParameterDefinition)([ParameterDefinitionImpl('slot',pointer,None),ParameterDefinitionImpl('tag',byte,None)]))
        callback=PointerDataType(definition,machine.program.getDataTypeManager())
        parameter_sets={'choice':[('choice',uint)],'none':[],'callback':[],'pointer':[('slot',pointer)]}
        source=[]
        tx=machine.program.startTransaction('authentic alias fixture source declarations')
        try:
            api.createMemoryBlock('disjoint_data',machine.address(0x6000),JArray(JByte)(bytes(8)),False)
            if case.get('escaped_global'):
                api.createData(machine.address(0x3000),pointer)
                api.createLabel(machine.address(0x3000),'escaped_slot',True)
            for name,address,_,_ in entries:
                fn=api.createFunction(machine.address(address),name);assert fn is not None
                parameters=parameter_sets[case['params']]
                result=wide if name=='dispatch' else void
                if name=='child':result=byte
                if name=='subject' and case['params']=='callback':parameters=[('callback',callback)]
                if name=='writer':parameters=[('slot',pointer)]+([('tag',byte)]if case['params']=='callback' else [])
                fn.updateFunction('__stdcall',ReturnParameterImpl(result,machine.program),Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,False,SourceType.USER_DEFINED,JArray(Variable)([ParameterImpl(n,t,machine.program)for n,t in parameters]))
                if name=='child':assert fn.getParameterCount()==0 and str(fn.getReturn().getVariableStorage())=='AL:1'
                source.append({'name':name,'signature':str(fn.getSignature()),'return_storage':str(fn.getReturn().getVariableStorage()),'parameters':[(str(p.getName()),str(p.getVariableStorage()),int(p.getDataType().getLength()))for p in fn.getParameters()]})
        finally:machine.program.endTransaction(tx,True)
        row['source']=source;row['machine']=[]
        for incoming,wanted in case['vectors']:
            emulator=machine.EmulatorHelper(machine.program)
            try:
                emulator.writeRegister('RDI',incoming);emulator.writeRegister('RBP',0x1122334455667788);emulator.writeRegister('RSP',0x7fe0)
                emulator.writeMemory(machine.address(0x7fe0),JArray(JByte)((0x7ff0).to_bytes(8,'little')))
                emulator.setBreakpoint(machine.address(0x7ff0));assert emulator.run(machine.address(0x1000),None,machine.monitor),str(emulator.getLastError())
                assert emulator.getExecutionAddress()==machine.address(0x7ff0)
                actual=int(str(emulator.readRegister('RAX')))&((1<<64)-1)
                assert actual==wanted,(case['name'],incoming,actual,wanted)
                restored=int(str(emulator.readRegister('RBP')))&((1<<64)-1)
                assert restored==0x1122334455667788,('outer caller violated its own preserved-register ABI',restored)
                stored=int.from_bytes(bytes(int(v)&255 for v in emulator.readMemory(machine.address(0x6000),8)),'little')
                assert stored==(7 if case['params']=='pointer' else 0),(case['name'],stored)
                escaped=None
                if case.get('escaped_global'):
                    escaped=int.from_bytes(bytes(int(v)&255 for v in emulator.readMemory(machine.address(0x3000),8)),'little')
                    assert escaped==0x7fc8,escaped
                row['machine'].append({'incoming_RDI':incoming,'result':actual,'outer_RBP_restored':restored,'disjoint_data':stored,'escaped_frame_pointer':escaped})
            finally:emulator.dispose()
        row['machine_completed']=True
        return image,entries
    finally:machine.close()

# Machine imports must happen after the JVM is started, as in the existing oracle.
start_ghidra()
for case in cases:
    if args.case!='all' and args.case!=case['name']:continue
    out=args.out/case['name'];out.mkdir();row={'case':case['name'],'completed':False,'commands':[]};report['cases'].append(row)
    def invoke(command):
        command=list(map(str,command));p=subprocess.run(command,cwd='/tmp',capture_output=True,text=True,timeout=240)
        value={'command':command,'status':p.returncode,'stdout':p.stdout,'stderr':p.stderr};row['commands'].append(value);return value
    try:
        image,entries=machine_case(case,row)
        binary=out/case['name'];binary.write_bytes(image)
        row['instructions']=[{'name':n,'entry':pc,'bytes':code.hex()}for n,pc,code,_ in entries]
        if args.machine_only:
            row['completed']=True;continue
        declarations={'dispatch':('unsigned long long dispatch(unsigned int choice)'if case['params']=='choice'else 'unsigned long long dispatch(unsigned long long *slot)'if case['params']=='pointer'else 'unsigned long long dispatch(void)'),
          'subject':('void subject(unsigned int choice)'if case['params']=='choice'else 'void subject(unsigned long long *slot)'if case['params']=='pointer'else 'void subject(Writer callback)'if case['params']=='callback'else 'void subject(void)'),
          'writer':('void writer(unsigned long long *slot,unsigned char tag)'if case['params']=='callback'else 'void writer(unsigned long long *slot)'),
          'child':'unsigned char child(void)'}
        common=['--raw-image','--target','x86:LE:64:default:gcc','--base','0x1000','--sleighpath',root/'specs','--assert-strict']
        if case['params']=='callback':common+=['--assert','typedef typedef void (*Writer)(unsigned long long *slot,unsigned char tag);']
        if case.get('escaped_global'):common+=['--assert','data 0x3000 unsigned long long *escaped_slot']
        for name,pc,code,_ in entries:common+=['--addr',hex(pc),'--define-function',f'{pc:#x}-{pc+len(code):#x}={name}','--assert','prototype '+name+' '+declarations[name]]
        meta=invoke([args.cli,'decompile-all',binary,'--json',*common]);assert meta['status']==0,meta
        metadata=json.loads(meta['stdout']);(out/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
        assert len(metadata['functions'])==len(entries),metadata
        assert {f['name']for f in metadata['functions']}=={entry[0]for entry in entries},metadata
        assert all(f.get('error')is None and f.get('code')for f in metadata['functions']),metadata
        project=out/'project';export=invoke([args.cli,'decompile-project',binary,'-o',project,*common])
        assert export['status']==0,export
        for provider,_,_,_ in entries:require_provider_body(project/(case['name']+'.c'),provider)
        if case['allow_boundary']:
            row['executable_extension_contract']='EX12/EXT03 investigation-only physical frame-state lowering'
        try:
            driver=out/'consumer.c';driver.write_text('#include "'+case['name']+'.h"\n#include <stdint.h>\n#include <stdlib.h>\n#include <string.h>\nint main(void){'+case['driver']+'return 0;}\n')
            row['emitted_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in [project/(case['name']+'.c'),project/(case['name']+'.h')]}
            failures=[]
            for opt in ['-O0','-O2']:
                try:
                    exe=out/('consumer'+opt);built=invoke([tool('cc'),'-std=c11','-Wall','-Wextra','-Werror=uninitialized','-Werror=incompatible-pointer-types','-Werror=implicit-function-declaration',opt,'-I',project,project/(case['name']+'.c'),driver,'-o',exe]);assert built['status']==0,built
                    ran=invoke([exe]);assert ran['status']==0,ran
                except Exception:
                    failures.append({'optimization':opt,'failure':traceback.format_exc()})
            assert not failures,failures
            row['unchanged_c_executed']=True
        except Exception:
            if not case['allow_boundary']:raise
            row['executable_extension_failure']=traceback.format_exc()
        row['completed']=True
    except BaseException:row['failure']=traceback.format_exc()
    finally:
        (out/'report.json').write_text(json.dumps(row,indent=2)+'\n');print(json.dumps({'case':case['name'],'completed':row['completed'],'machine_completed':row.get('machine_completed'), 'failure':row.get('failure')}),flush=True)
report['completed']=all(row['completed']for row in report['cases'])
(args.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
if not report['completed']:raise SystemExit(1)
