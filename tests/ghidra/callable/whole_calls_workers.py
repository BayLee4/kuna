#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import traceback
from whole_calls import Machine
from support import require_provider_body, require_absent_provider_body, start_ghidra


def elf_symbols(binary):
    image = binary.read_bytes()
    assert image[:6] == b'\x7fELF\x02\x01'
    shoff = struct.unpack_from('<Q', image, 40)[0]
    entsize, count = struct.unpack_from('<HH', image, 58)
    sections = [struct.unpack_from('<IIQQQQIIQQ', image, shoff + i * entsize) for i in range(count)]
    symbols = {}
    for section in sections:
        if section[1] != 2:
            continue
        strings = sections[section[6]]
        names = image[strings[4]:strings[4]+strings[5]]
        for offset in range(section[4], section[4]+section[5], section[9]):
            name, info, _, _, address, size = struct.unpack_from('<IBBHQQ', image, offset)
            if info & 15 == 2 and size:
                symbols[names[name:names.index(0, name)].decode()] = address
    return symbols


class ElfMachine(Machine):
    def __init__(self, binary, out):
        pyghidra = start_ghidra()
        from jpype import JArray, JByte
        from ghidra.app.emulator import EmulatorHelper
        from ghidra.util.task import ConsoleTaskMonitor
        self.context = pyghidra.open_program(binary, project_location=out, project_name='machine-elf', analyze=False)
        api = self.context.__enter__()
        self.program = api.getCurrentProgram()
        self.EmulatorHelper = EmulatorHelper
        self.monitor = ConsoleTaskMonitor()
        self.address = self.program.getAddressFactory().getDefaultAddressSpace().getAddress
        tx = self.program.startTransaction('emulation stack')
        try:
            api.createMemoryBlock('acceptance_stack', self.address(0x7000), JArray(JByte)(bytes(0x1000)), False)
        finally:
            self.program.endTransaction(tx, True)
    def close(self):
        self.context.__exit__(None, None, None)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cli', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--mode', choices=('serial', 'jobs2', 'stream'), default='jobs2')
    parser.add_argument('--exclude-dispatch', action='store_true')
    parser.add_argument('--machine-only', action='store_true')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    report = {'scope': 'authentic linked ELF/DWARF, supported object CLI, unchanged emitted C',
              'mode': args.mode,
              'cli_sha256': hashlib.sha256(args.cli.read_bytes()).hexdigest(),
              'elf_sha256': hashlib.sha256(args.binary.read_bytes()).hexdigest(),
              'dispatch_excluded': args.exclude_dispatch,
              'commands': [], 'completed': False}
    def invoke(command, expect=0):
        result = subprocess.run(list(map(str, command)), cwd='/tmp', capture_output=True, text=True, timeout=240)
        row = {'command':list(map(str,command)), 'status':result.returncode, 'stdout':result.stdout, 'stderr':result.stderr}
        report['commands'].append(row)
        (args.out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
        if expect is not None:
            assert (result.returncode != 0 if expect == 'nonzero' else result.returncode == expect), row
        return row
    try:
        symbols = elf_symbols(args.binary)
        report['linked_symbols'] = symbols
        machine = ElfMachine(args.binary, args.out)
        cases = 0
        try:
            for which, name in [(0,'byte_target'),(1,'word_target')]:
                assert machine.call(symbols['choose'], which) == symbols[name]
                assert machine.call(symbols['choose'], which) == symbols[name]
            for name, want in [('direct_dirty',0),('direct_clean',1),('ambient_dirty',0),('ambient_clean',1)]:
                assert machine.call(symbols[name]) == want
            assert machine.call(symbols['forward'],symbols['byte_target']) == 1
            assert machine.call(symbols['forward'],symbols['word_target']) == 0
            for upper in (0,0x10000,0x1234567800000000):
                for low in range(256):
                    raw = upper | low
                    for name, mask in [('ambient',0xffffffff),('wide_ambient',0xffffffff),('bool_byte',0xff)]:
                        assert machine.call(symbols[name],raw) == int((raw & mask)==85), (name,raw)
                    for name, mask in [('carry_ambient',0xffffffff),('carry_bool',0xff)]:
                        assert machine.call(symbols[name],raw) == int((raw & mask)==85), (name,raw)
                    for which in (0,1):
                        want = int((raw & (0xffffffff if which else 0xff))==85)
                        assert machine.call(symbols['dispatch'],raw,which)==want, (raw,which)
                        target = symbols['word_target' if which else 'byte_target']
                        assert machine.call(symbols['invoke'],raw,target)==want, (raw,which,target)
                        assert machine.call(symbols['carry_dispatch'],raw,which)==want, (raw,which)
                        assert machine.call(symbols['carry_invoke'],raw,target)==want, (raw,which,target)
                        cases += 1
        finally:
            machine.close()
        report['machine']={'dispatch_cases':cases,'invoke_cases':cases,'ambient_cases':768,'wide_ambient_cases':768,'bool_cases':768,'pointer_identity':True,'native_byte':1,'native_word':0}
        if args.machine_only:
            report['machine_only'] = True
            (args.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
            print(json.dumps(report,indent=2))
            return
        names=['choose','byte_target','word_target','invoke','dispatch','direct_dirty','direct_clean','ambient','ambient_dirty','ambient_clean','bool_byte','wide_ambient',
               'carry_dispatch','carry_invoke','carry_ambient','carry_bool']
        if args.exclude_dispatch:
            names.remove('dispatch')
            names.remove('carry_dispatch')
        jobs = ['--jobs', '2'] if args.mode == 'jobs2' else []
        common=['--functions',','.join(names),*jobs,'--language','c']
        export_mode = ['--stream'] if args.mode == 'stream' else []
        project=args.out/'project'
        invoke([args.cli,'decompile-project',args.binary,'-o',project,*common,*export_mode])
        metadata=json.loads(invoke([args.cli,'decompile-all',args.binary,'--json',*common])['stdout'])
        (args.out/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
        expected={'choose':[('which',4)],'byte_target':[('value',1)],'word_target':[('value',1)],'invoke':[('value',1),('callback',8)],'dispatch':[('value',1),('which',4)],'direct_dirty':[],'direct_clean':[],'ambient':[],'ambient_dirty':[],'ambient_clean':[],'bool_byte':[('value',1)],'wide_ambient':[('bits',8)]}
        expected.update({'carry_dispatch':[('bits',8),('which',4)],'carry_invoke':[('bits',8),('callback',8)],
                         'carry_ambient':[('bits',8)],'carry_bool':[('bits',8)]})
        if args.exclude_dispatch:
            del expected['dispatch']
            del expected['carry_dispatch']
        try:
            assert len(metadata['functions']) == len(expected), metadata
            assert {function['name'] for function in metadata['functions']} == set(expected), metadata
            actual={}
            for function in metadata['functions']:
                assert function.get('error') is None, function
                params=sorted((v for v in function['variables'] if v['kind']=='arg'),key=lambda v:v['arg_index'])
                assert [v['arg_index'] for v in params] == list(range(len(params))), function
                actual[function['name']]=[(v['name'],v['size']) for v in params]
            assert actual==expected, (actual,expected)
            report['source_metadata']=actual
        except Exception:
            report['source_metadata_failure']=traceback.format_exc()
        stem=args.binary.name
        emitted_c=project/(stem+'.c'); emitted_h=project/(stem+'.h')
        for name in expected:
            require_provider_body(emitted_c, name)
        report['emitted_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (emitted_c,emitted_h)}
        driver=args.out/'consumer.c'
        dispatch_check='' if args.exclude_dispatch else 'if(carry_dispatch(raw,which)!=want) return 14;'
        narrow_dispatch='' if args.exclude_dispatch else 'if(dispatch(value,which)!=want)return 20;'
        driver.write_text('#include <stdint.h>\n#include <stdio.h>\n#include "'+stem+'.h"\n'+'''static unsigned native_calls;
static int consumer_native_callback(Flags value) {
 ++native_calls;return (int)value*3+17;
}
int main(void) {
 if(choose(0)!=choose(0)||choose(1)!=choose(1)||choose(0)==choose(1))return 11;
 if(direct_dirty()!=0||direct_clean()!=1||ambient_dirty()!=0||ambient_clean()!=1)return 12;
 if(bool_byte(0)!=0||bool_byte(1)!=0)return 19;
 for(unsigned low=0;low<256;++low){
  Flags value=(Flags)low;int want=low==85;
  if(byte_target(value)!=want||word_target(value)!=want)return 18;
  if(invoke(value,consumer_native_callback)!=(int)low*3+17)return 22;
  for(unsigned which=0;which<2;++which){
   if(invoke(value,choose(which))!=want)return 21;
'''+narrow_dispatch+'''
  }
 }
 const uint64_t upper[]={0,UINT64_C(0x10000),UINT64_C(0x1234567800000000)};
 unsigned checked=0;
 for(unsigned p=0;p<3;++p)for(unsigned low=0;low<256;++low){
  uint64_t raw=upper[p]|low;
  if(carry_ambient(raw)!=((uint32_t)raw==85)||wide_ambient(raw)!=((uint32_t)raw==85)||carry_bool(raw)!=((uint8_t)raw==85))return 13;
  if(carry_invoke(raw,consumer_native_callback)!=(int)low*3+17)return 23;
  for(unsigned which=0;which<2;++which){
   int want=which?(uint32_t)raw==85:(uint8_t)raw==85;
   if(carry_invoke(raw,choose(which))!=want)return 15;
'''+dispatch_check+'''
   ++checked;
  }
 }
 if(native_calls!=1024)return 24;
 printf("checked=%u\\n",checked);return 0;
}
''')
        report['consumer_failures']=[]
        for opt in ('-O0','-O2'):
            for char_mode in ('-fsigned-char', '-funsigned-char'):
                try:
                    exe=args.out/('consumer'+opt+char_mode)
                    invoke(['cc','-std=c11','-Wall','-Wextra','-Werror=uninitialized','-Werror=incompatible-pointer-types','-Werror=implicit-function-declaration',opt,char_mode,'-I',project,emitted_c,driver,'-o',exe])
                    invoke([exe])
                except BaseException:
                    report['consumer_failures'].append({'optimization':opt,'char_mode':char_mode,
                                                       'failure':traceback.format_exc()})
        assert not report['consumer_failures'],report['consumer_failures']
        report['behavioral_checks_completed']=True
    except BaseException:
        report['failure']=traceback.format_exc()
    if args.mode == 'serial':
        try:
            corrected=args.out/'typed-parameter-project'
            corrected_names=('word_target','direct_dirty','direct_clean')
            invoke([args.cli,'decompile-project',args.binary,'-o',corrected,
                    '--functions',','.join(corrected_names),'--language','c',
                    '--assert','type word_target::value float sample','--assert-strict'])
            corrected_body=corrected/(args.binary.name+'.c')
            for name in corrected_names:
                require_provider_body(corrected_body,name)
            implementations=set(re.findall(
                r'\bstatic\s+int\s+([A-Za-z_]\w*)\s*\(\s*float\s+sample\s*\)',
                corrected_body.read_text()))
            assert len(implementations)==1, implementations
            implementation=implementations.pop()
            signature=args.out/'typed-parameter-unit.c'
            signature.write_text('#include "'+corrected_body.name+'"\n'
                '_Static_assert(_Generic(&'+implementation+', int (*)(float): 1, default: 0),'
                '"explicit private correction must survive publication");\n')
            corrected_driver=args.out/'typed-parameter-consumer.c'
            corrected_driver.write_text('#include "'+args.binary.name+'.h"\n'
                '_Static_assert(_Generic(&word_target, int (*)(Flags): 1, default: 0),'
                '"public source parameter must remain Flags");\n'
                'int main(void){if(direct_clean()!=1)return 1;if(direct_dirty()!=0)return 2;'
                'for(unsigned value=0;value<256;++value)'
                'if(word_target((Flags)value)!=(value==85))return 3;return 0;}\n')
            for opt in ('-O0','-O2'):
                executable=args.out/('typed-parameter'+opt)
                invoke(['cc','-std=c11','-Wall','-Wextra','-Werror=uninitialized',
                        '-Werror=incompatible-pointer-types','-Werror=implicit-function-declaration',
                        opt,'-I',corrected,signature,corrected_driver,'-o',executable])
                invoke([executable])
            report['typed_parameter']={'private_type':'float','public_type':'Flags',
                                       'direct_clean':1,'direct_dirty':0,'public_byte_values':256}
        except BaseException:
            report['typed_parameter_failure']=traceback.format_exc()
    try:
        jobs = ['--jobs', '2'] if args.mode == 'jobs2' else []
        export_mode = ['--stream'] if args.mode == 'stream' else []
        native_common=['--functions','forward',*jobs,'--language','c']
        native=json.loads(invoke([args.cli,'decompile-all',args.binary,'--json',*native_common])['stdout'])['functions'][0]
        assert native.get('error') is None and native.get('code'), native
        assert [(v['name'],v['size']) for v in native['variables'] if v['kind']=='arg']==[('callback',8)],native
        exported=invoke([args.cli,'decompile-project',args.binary,'-o',args.out/'native-project',
                         *native_common,*export_mode])
        native_body=args.out/'native-project'/(args.binary.name+'.c')
        require_provider_body(native_body,'forward')
        for name in symbols:
            if name!='forward':
                require_absent_provider_body(native_body,name)
        report['native_boundary']={'project_status':exported['status']}
        report['completed']=not any(key in report for key in (
            'failure','source_metadata_failure','typed_parameter_failure'))
    except BaseException:
        report['native_boundary_failure']=traceback.format_exc()
    finally:
        (args.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report,indent=2))
    if not report['completed']:
        raise SystemExit(1)

if __name__=='__main__':
    main()
