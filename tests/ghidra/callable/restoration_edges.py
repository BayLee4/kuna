#!/usr/bin/env python3
"""Original restoration controls; ambient-EBX executable lowering is conditional."""
import argparse
import hashlib
import json
from pathlib import Path
from support import ROOT, cli as default_cli, output, tool, start_ghidra, execute_i386_publication, require_provider_body
import subprocess
import traceback

parser = argparse.ArgumentParser()
parser.add_argument('--cli', type=Path)
parser.add_argument('--out', type=Path)
parser.add_argument('--case', choices=('all','saved_slot','branch_copy','custom_rbx','join_return'), default='all')
args = parser.parse_args()
args.cli = (args.cli or default_cli()).resolve(); args.out = (args.out or output("restoration_edges")/"run").resolve()
args.out.mkdir(parents=True, exist_ok=False)
base = ROOT
report = {'scope': 'Original machine/source/project controls; branch/custom/JOIN C is mandatory, ambient-EBX C is investigation-only.',
          'cli_sha256': hashlib.sha256(args.cli.read_bytes()).hexdigest(), 'completed': False, 'cases': []}

start_ghidra()
from jpype import JArray, JByte
from java.lang import Object
from ghidra.app.emulator import EmulatorHelper
from ghidra.program.database import ProgramDB
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.data import IntegerDataType, UnsignedIntegerDataType, UnsignedLongLongDataType
from ghidra.program.model.lang import LanguageID, CompilerSpecID
from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl, Variable
from ghidra.program.model.symbol import SourceType
from ghidra.program.util import DefaultLanguageService
from ghidra.util.task import ConsoleTaskMonitor
monitor = ConsoleTaskMonitor()
integer, uint, wide = IntegerDataType.dataType, UnsignedIntegerDataType.dataType, UnsignedLongLongDataType.dataType
values = [0,7,0x1234,0x5678,0x80000000,0xffffffff]
cases = [
 {'name':'saved_slot','bits':32,'code':'53bb07000000e8f50000005bc3','prototype':'int __cdecl subject(void)','types':[], 'result':integer,
  'child':'8b442404c3','extra':[], 'expected_params':[],
  'machine':[({'EBX':v},v) for v in values],
  'driver':None},
 {'name':'branch_copy','bits':64,'code':'85d274054889f0eb034889f8c3','prototype':'unsigned long long subject(unsigned long long first,unsigned long long second,unsigned int which)',
  'types':[('first',wide),('second',wide),('which',uint)],'result':wide,'extra':[], 'expected_params':[('first',8),('second',8),('which',4)],
  'machine':[({'RDI':a,'RSI':b,'EDX':c},b if c else a) for a,b in [(0,7),(7,0),(0x123456789abcdef0,0x76543210fedcba98)] for c in [0,1,0xffffffff]],
  'driver':'const uint64_t pairs[][2]={{0,7},{7,0},{UINT64_C(0x123456789abcdef0),UINT64_C(0x76543210fedcba98)}}; const unsigned flags[]={0,1,UINT32_MAX}; for(unsigned i=0;i<3;++i) for(unsigned j=0;j<3;++j) if(subject(pairs[i][0],pairs[i][1],flags[j])!=pairs[i][flags[j]!=0]) return 2;'},
 {'name':'custom_rbx','bits':64,'code':'4889fbc3','prototype':'unsigned long long subject(unsigned long long value)',
  'types':[('value',wide)],'result':wide,'extra':['return subject::%RBX unsigned long long'], 'expected_params':[('value',8)],
  'machine':[({'RDI':v},v) for v in [0,7,0x123456789abcdef0,0x76543210fedcba98]],
  'driver':'const uint64_t values[]={0,7,UINT64_C(0x123456789abcdef0),UINT64_C(0x76543210fedcba98)}; for(unsigned i=0;i<4;++i) if(subject(values[i])!=values[i]) return 3;'},
 {'name':'join_return','bits':32,'code':'8b4424048b542408c3','prototype':'unsigned long long __cdecl subject(unsigned int low,unsigned int high)',
  'types':[('low',uint),('high',uint)],'result':wide,'extra':[], 'expected_params':[('low',4),('high',4)],
  'machine':[({'stack_arg0':lo,'stack_arg1':hi},(hi<<32)|lo) for lo,hi in [(0,7),(7,0),(0x12345678,0x76543210),(0xffffffff,0x80000000)]],
  'driver':'const uint32_t pairs[][2]={{0,7},{7,0},{UINT32_C(0x12345678),UINT32_C(0x76543210)},{UINT32_MAX,UINT32_C(0x80000000)}}; for(unsigned i=0;i<4;++i) if(subject(pairs[i][0],pairs[i][1])!=(((uint64_t)pairs[i][1]<<32)|pairs[i][0])) return 4;'},
]

def original_machine(case, row):
    language = DefaultLanguageService.getLanguageService().getLanguage(LanguageID(f"x86:LE:{case['bits']}:default"))
    owner = Object()
    program = ProgramDB(case['name'], language, language.getCompilerSpecByID(CompilerSpecID('gcc')), owner)
    address = program.getAddressFactory().getDefaultAddressSpace().getAddress
    api = FlatProgramAPI(program, monitor)
    try:
        tx = program.startTransaction('authentic restoration source and instructions')
        try:
            entries = [('subject',0x1000,case['code'],case['types'],case['result'])]
            if 'child' in case: entries.append(('child',0x1100,case['child'],[('value',integer)],integer))
            source = []
            for name,entry,code,types,result in entries:
                block = api.createMemoryBlock(name,address(entry),JArray(JByte)(bytes.fromhex(code)),False)
                block.setExecute(True)
                assert api.disassemble(address(entry))
                fn = api.createFunction(address(entry),name)
                assert fn is not None
                parameters = [ParameterImpl(n,t,program) for n,t in types]
                ret = ReturnParameterImpl(result,program)
                update = Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS
                if case['name']=='custom_rbx':
                    parameters = [ParameterImpl('value',wide,program.getRegister('RDI'),program)]
                    ret = ReturnParameterImpl(wide,program.getRegister('RBX'),program)
                    update = Function.FunctionUpdateType.CUSTOM_STORAGE
                fn.updateFunction('__cdecl' if case['bits']==32 else '__stdcall',ret,update,False,SourceType.USER_DEFINED,JArray(Variable)(parameters))
                storage = fn.getReturn().getVariableStorage()
                return_pieces = [(str(language.getRegister(v.getAddress(),v.getSize()).getName()),int(v.getSize())) for v in storage.getVarnodes()]
                if case['name']=='custom_rbx': assert return_pieces==[('RBX',8)],return_pieces
                if case['name']=='join_return': assert set(return_pieces)=={('EDX',4),('EAX',4)},return_pieces
                source.append({'name':name,'signature':str(fn.getSignature()),'return_storage':str(storage),'return_pieces':return_pieces,'parameters':[(str(p.getName()),str(p.getVariableStorage()),int(p.getDataType().getLength())) for p in fn.getParameters()]})
            api.createMemoryBlock('stack',address(0x7000),JArray(JByte)(bytes(0x1000)),False)
        finally:
            program.endTransaction(tx,True)
        row['source']=source
        results=[]
        for registers,wanted in case['machine']:
            emu=EmulatorHelper(program)
            try:
                for register,value in registers.items():
                    if not register.startswith('stack_arg'): emu.writeRegister(register,value)
                emu.writeRegister('ESP' if case['bits']==32 else 'RSP',0x7fe0)
                emu.writeMemory(address(0x7fe0),JArray(JByte)((0x7ff0).to_bytes(case['bits']//8,'little')))
                if case['name']=='join_return':
                    for slot in (0,1):
                        emu.writeMemory(address(0x7fe4+slot*4),JArray(JByte)(registers['stack_arg'+str(slot)].to_bytes(4,'little')))
                emu.setBreakpoint(address(0x7ff0))
                assert emu.run(address(0x1000),None,monitor),str(emu.getLastError())
                assert emu.getExecutionAddress()==address(0x7ff0)
                if case['name']=='custom_rbx': actual=int(str(emu.readRegister('RBX')))&((1<<64)-1)
                elif case['name']=='join_return': actual=((int(str(emu.readRegister('EDX')))&0xffffffff)<<32)|(int(str(emu.readRegister('EAX')))&0xffffffff)
                else: actual=int(str(emu.readRegister('EAX' if case['bits']==32 else 'RAX')))&((1<<case['bits'])-1)
                assert actual==wanted,(case['name'],registers,actual,wanted)
                if case['name']=='saved_slot': assert int(str(emu.readRegister('EBX')))&0xffffffff==registers['EBX']
                results.append({'inputs':registers,'result':actual})
            finally:
                emu.dispose()
        row['machine']=results
    finally:
        program.release(owner)

def generated_saved_slot(row, out, project, invoke):
    from whole_calls_workers import ElfMachine
    from java.math import BigInteger
    header, body = project/'saved_slot.h', project/'saved_slot.c'
    row['emitted_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (header, body)}
    def consume(opt):
        obj, binary = out/('saved'+opt+'.o'), out/('saved'+opt+'.elf')
        built = invoke([tool('clang'),'--target=i386-unknown-linux-gnu','-std=c11',
                        '-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pic',
                        '-fno-pie','-Wall','-Wextra','-Werror=uninitialized',
                        '-Werror=incompatible-pointer-types','-Werror=implicit-function-declaration',opt,'-I',project,
                        '-c',body,'-o',obj])
        assert built['status']==0,built
        linked = invoke([tool('ld.lld'),'-m','elf_i386','--image-base=0','-Ttext=0x1000',
                         '-e','subject','--build-id=none',obj,'-o',binary])
        assert linked['status']==0,linked
        machine_directory=out/('machine'+opt)
        machine_directory.mkdir()
        machine=ElfMachine(binary,machine_directory)
        try:
            entries=list(machine.program.getSymbolTable().getSymbols('subject'))
            assert len(entries)==1,entries
            for value in values:
                emulator=machine.EmulatorHelper(machine.program)
                try:
                    for register,initial in [('EBX',value),('ESP',0x7fe0)]:
                        emulator.writeRegister(register,BigInteger(str(initial)))
                    emulator.writeMemory(machine.address(0x7fe0),JArray(JByte)((0x7ff0).to_bytes(4,'little')))
                    emulator.setBreakpoint(machine.address(0x7ff0))
                    assert emulator.run(entries[0].getAddress(),None,machine.monitor),str(emulator.getLastError())
                    actual=int(str(emulator.readRegister('EAX')))&0xffffffff
                    assert actual==value and int(str(emulator.readRegister('EBX')))&0xffffffff==value,(opt,value,actual)
                    assert int(str(emulator.readRegister('ESP')))==0x7fe4
                    row.setdefault('generated_machine',[]).append({'optimization':opt,'incoming_EBX':value,'result':actual})
                finally:emulator.dispose()
        finally:machine.close()
    failures=[]
    for opt in ('-O0','-O2'):
        try:
            consume(opt)
        except Exception:
            failures.append({'optimization':opt,'failure':traceback.format_exc()})
    assert not failures,failures

for case in cases:
    if args.case!='all' and case['name']!=args.case: continue
    out=args.out/case['name'];out.mkdir()
    row={'case':case['name'],'completed':False,'commands':[]};report['cases'].append(row)
    def invoke(command):
        command=list(map(str,command))
        result=subprocess.run(command,cwd='/tmp',capture_output=True,text=True,timeout=240)
        record={'command':command,'status':result.returncode,'stdout':result.stdout,'stderr':result.stderr};row['commands'].append(record)
        return record
    try:
        original_machine(case,row)
        code=bytes.fromhex(case['code']);image=bytearray(0x105 if 'child'in case else len(code));image[:len(code)]=code
        if 'child'in case:image[0x100:]=bytes.fromhex(case['child'])
        binary=out/case['name'];binary.write_bytes(image)
        common=['--raw-image','--target',f"x86:LE:{case['bits']}:default:gcc",'--base','0x1000','--sleighpath',base/'specs','--addr','0x1000','--define-function',f'0x1000-{0x1000+len(code):#x}=subject','--assert-strict','--assert','prototype subject '+case['prototype']]
        if 'child'in case:common+=['--addr','0x1100','--define-function','0x1100-0x1105=child','--assert','prototype child int __cdecl child(int value)']
        for extra in case['extra']:common+=['--assert',extra]
        meta=invoke([args.cli,'decompile-all',binary,'--json',*common]);assert meta['status']==0,meta
        metadata=json.loads(meta['stdout']);(out/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
        assert len(metadata['functions'])==(2 if 'child'in case else 1),metadata
        assert {f['name']for f in metadata['functions']}==({'subject','child'}if 'child'in case else{'subject'}),metadata
        subject=next(f for f in metadata['functions'] if f['name']=='subject')
        assert subject.get('error') is None and subject.get('code'),subject
        parameters=sorted((v for v in subject['variables'] if v['kind']=='arg'),key=lambda v:v['arg_index'])
        assert [(v['name'],v['size']) for v in parameters]==case['expected_params'],parameters
        project=out/'project'
        export=invoke([args.cli,'decompile-project',binary,'-o',project,*common])
        assert export['status']==0,export
        for provider in ({'subject','child'}if 'child'in case else{'subject'}):
            require_provider_body(project/(case['name']+'.c'),provider)
        if case['name']=='saved_slot':
            row['executable_extension_contract']='EX12/EXT03 investigation-only ambient EBX lowering'
            try:
                generated_saved_slot(row,out,project,invoke)
                row['unchanged_c_executed']=True
            except Exception:
                row['executable_extension_failure']=traceback.format_exc()
        else:
            driver=out/'consumer.c';driver.write_text('#include "'+case['name']+'.h"\n#include <stdint.h>\nint main(void){'+case['driver']+'return 0;}\n')
            if case['bits']==32:
                execute_i386_publication(row,out,project/(case['name']+'.h'),project/(case['name']+'.c'),driver,False)
            else:
                row['emitted_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [project/(case['name']+'.c'),project/(case['name']+'.h')]}
                failures=[]
                for opt in ['-O0','-O2']:
                    try:
                        exe=out/('consumer'+opt)
                        built=invoke([tool('cc'),'-std=c11','-Wall','-Wextra','-Werror=uninitialized','-Werror=incompatible-pointer-types','-Werror=implicit-function-declaration',opt,'-I',project,project/(case['name']+'.c'),driver,'-o',exe]);assert built['status']==0,built
                        ran=invoke([exe]);assert ran['status']==0,ran
                    except Exception:
                        failures.append({'optimization':opt,'failure':traceback.format_exc()})
                assert not failures,failures
            row['unchanged_c_executed']=True
        row['behavioral_checks_completed']=True
        row['completed']=True
    except BaseException:
        row['failure']=traceback.format_exc()
    finally:
        (out/'report.json').write_text(json.dumps(row,indent=2)+'\n')
        print(json.dumps({'case':case['name'],'completed':row['completed'],'failure':row.get('failure')}),flush=True)
report['completed']=all(row['completed'] for row in report['cases'])
(args.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
if not report['completed']:raise SystemExit(1)
