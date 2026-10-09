#!/usr/bin/env python3
"""Observe real machine GP effects/implicit consumers across two loaded calls."""
import argparse,hashlib,json,traceback
from pathlib import Path
from whole_calls_workers import ElfMachine
p=argparse.ArgumentParser();p.add_argument('--construction',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--scope',choices=['roles','inherited','private'],default='roles');a=p.parse_args();a.out=a.out.resolve();a.out.mkdir(parents=True,exist_ok=False);construction=json.loads(a.construction.read_text());r={'completed':False,'cases':[],'selected_scope':a.scope,'scope':'Original linked MIPS32 machine bodies, genuine direct calls and mutable function-pointer slots. No callee substitution, register injection between instructions, ABI clearing, or source-formal GP arguments.','partial_write_scope':'Genuine lone LWR gp,3(base) merges a new low byte with old dirty upper24bits. Raw pcode has full GP output and explicit old-GP read, NOT a byte-sized subregister output. No LWL pair or context shortcut.'}
try:
 from jpype import JArray,JByte
 # Imports below require the genuine ElfMachine startup first.
 for image in construction['cases']:
  if a.scope!='roles'and image['readonly_value']!=0:continue
  directory=a.out/image['label'];directory.mkdir();binary=Path(image['binary']);assert hashlib.sha256(binary.read_bytes()).hexdigest()==image['binary_sha256'];m=ElfMachine(binary,directory)
  try:
   from ghidra.pcode.emu import PcodeEmulator,EmulatorUtilities
   from ghidra.pcode.exec import PcodeExecutorStatePiece
   from ghidra.program.flatapi import FlatProgramAPI
   from ghidra.program.model.pcode import PcodeOp
   program=m.program;assert str(program.getLanguageID()).startswith('MIPS:LE:32:')
   symbols={str(s.getName()):int(s.getAddress().getOffset())for s in program.getSymbolTable().getAllSymbols(True)}
   memory=program.getMemory();flag=m.address(symbols['readonly_flag']);assert not memory.getBlock(flag).isWrite();assert int(memory.getByte(flag))==image['readonly_value']
   assert int(memory.getInt(m.address(symbols['first_slot'])))&0xffffffff==symbols['dirty_gp']
   assert int(memory.getInt(m.address(symbols['second_slot'])))&0xffffffff==symbols['consume_gp']
   assert memory.getBlock(m.address(symbols['first_slot'])).isWrite()
   assert symbols['primary_value']&255==0 and symbols['alternate_value']&255==0
   assert symbols['primary_value']>>8!=symbols['alternate_value']>>8
   api=FlatProgramAPI(program,m.monitor);tx=program.startTransaction('decode original implicit consumer')
   try:
    assert api.disassemble(m.address(symbols['consume_gp']))
    assert api.disassemble(m.address(symbols['partial_merge']))
    if a.scope=='inherited':
     for entry in ['direct_gp_parent','direct_gp_read_parent']:assert api.disassemble(m.address(symbols[entry]))
    if a.scope=='private':
     for entry in ['private_gp_spill','private_gp_reload','private_gp_escape']:assert api.disassemble(m.address(symbols[entry]))
   finally:program.endTransaction(tx,True)
   load=program.getListing().getInstructionAt(m.address(symbols['consume_gp']));assert any(op.getOpcode()==PcodeOp.LOAD for op in load.getPcode())
   merge=program.getListing().getInstructionAt(m.address(symbols['partial_merge']))
   assert str(merge.getMnemonicString()).lower()=='lwr'
   gp=program.getRegister('gp');assert any(vn.isRegister()and vn.getOffset()==gp.getAddress().getOffset()for op in merge.getPcode()for vn in op.getInputs())
   selected=['caller_dirty','caller_full','caller_partial','caller_removed']if image['readonly_value']==0 else['caller_removed']
   if a.scope=='inherited':selected=['direct_gp_parent','direct_gp_read_parent']
   if a.scope=='private':selected=['private_gp_spill','private_gp_reload','private_gp_escape']
   for entry in selected:
    emulator=PcodeEmulator(program.getLanguage());EmulatorUtilities.loadProgram(emulator,program);thread=emulator.newThread();state=thread.getState()
    preserved=[('s0',0x12121212),('s1',0x23232323),('s2',0x34343434),('s3',0x45454545),('s4',0x56565656),('s5',0x67676767),('s6',0x78787878),('s7',0x89898989),('s8',0x98989898)]
    for register,value in [('sp',0x7fe0),('ra',0x7ff0),('t9',symbols[entry]),('gp',0x41414141),*preserved]:
     reg=program.getRegister(register);state.setVar(reg,JArray(JByte)(value.to_bytes(reg.getMinimumByteSize(),'little')))
    thread.overrideCounter(m.address(symbols[entry]));thread.overrideContextWithDefault()
    def register_value(name):
     raw=state.getVar(program.getRegister(name),PcodeExecutorStatePiece.Reason.INSPECT);return int.from_bytes(bytes(int(v)&255 for v in raw),'little')
    row={'entry':entry,'readonly_flag':image['readonly_value'],'binary_sha256':image['binary_sha256'],'symbols':symbols,'calls':[],'executed_instruction_addresses':[],'implicit_consumer_instruction':str(load),'implicit_consumer_pcode':[str(op)for op in load.getPcode()],'partial_merge_instruction':str(merge),'partial_merge_pcode':[str(op)for op in merge.getPcode()]};r['cases'].append(row)
    while thread.getCounter()!=m.address(0x7ff0):
     pc=int(thread.getCounter().getOffset());assert len(row['executed_instruction_addresses'])<256,row
     row['executed_instruction_addresses'].append(pc)
     observed_callees={symbols[name]:name for name in ['dirty_gp','consume_gp','dirty_gp_natural']if name in symbols}
     if pc in observed_callees and (a.scope!='natural'or pc!=symbols[entry]):row['calls'].append({'callee':observed_callees[pc],'GP':register_value('gp'),'T9':register_value('t9'),'SP':register_value('sp')})
     thread.stepInstruction()
    if a.scope=='inherited':
     assert [call['callee']for call in row['calls']]==['dirty_gp']
     assert row['calls'][0]['GP']==0x41414141
     original_ops=[op for instruction in program.getListing().getInstructions(m.address(symbols[entry]),True)if int(instruction.getAddress().getOffset())<symbols[entry+'_end']for op in instruction.getPcode()]
     assert not any(op.getOutput()is not None and op.getOutput().isRegister()and op.getOutput().getOffset()==gp.getAddress().getOffset()for op in original_ops)
     gp_reads=[op for op in original_ops if any(vn.isRegister()and vn.getOffset()==gp.getAddress().getOffset()for vn in op.getInputs())]
     assert bool(gp_reads)==(entry=='direct_gp_read_parent')
     calls=[op for op in original_ops if op.getOpcode()==PcodeOp.CALL]
     assert len(calls)==1 and int(calls[0].getInput(0).getOffset())==symbols['dirty_gp']
     row['parent_actual_raw_pcode']=[str(op)for op in original_ops]
     row['parent_own_GP_writes']=0;row['parent_own_GP_reads']=len(gp_reads)
     wanted=11 if entry=='direct_gp_parent'else 77
     final_gp=symbols['alternate_value']
    elif a.scope=='private':
     assert not row['calls']
     original_instructions=[instruction for instruction in program.getListing().getInstructions(m.address(symbols[entry]),True)if int(instruction.getAddress().getOffset())<symbols[entry+'_end']]
     original_ops=[op for instruction in original_instructions for op in instruction.getPcode()]
     assert not any(op.getOpcode()in [PcodeOp.CALL,PcodeOp.CALLIND]for op in original_ops)
     stores=[op for op in original_ops if op.getOpcode()==PcodeOp.STORE]
     loads=[op for op in original_ops if op.getOpcode()==PcodeOp.LOAD]
     assert len(stores)==(2 if entry=='private_gp_escape'else 1)
     assert len(loads)==(1 if entry=='private_gp_reload'else 0)
     def memory_word(address):
      data=state.getVar(m.address(address),4,False,PcodeExecutorStatePiece.Reason.INSPECT)
      return int.from_bytes(bytes(int(v)&255 for v in data),'little')
     assert memory_word(0x7fd8)==symbols['alternate_value']
     escaped=memory_word(symbols['escaped_slot']);assert escaped==(0x7fd8 if entry=='private_gp_escape'else 0)
     row['actual_private_spill']={'entry_SP':0x7fe0,'frame_SP':0x7fd0,'spill_address':0x7fd8,'spill_size':4,'stored_full_GP':memory_word(0x7fd8),'escaped_slot':symbols['escaped_slot'],'escaped_pointer':escaped}
     row['original_instruction_pcode']=[{'address':int(instruction.getAddress().getOffset()),'instruction':str(instruction),'pcode':[str(op)for op in instruction.getPcode()]}for instruction in original_instructions]
     wanted=symbols['alternate_value']if entry=='private_gp_reload'else 11 if entry=='private_gp_spill'else None
     final_gp=symbols['alternate_value']
    else:
     consumed=entry!='caller_removed'or image['readonly_value']!=0
     assert [call['callee']for call in row['calls']]==(['dirty_gp','consume_gp']if consumed else['dirty_gp'])
     assert row['calls'][0]['GP']==symbols['primary_value']
     if consumed:assert row['calls'][1]['GP']==symbols['primary_value'if entry=='caller_full'else'alternate_value']
     wanted=11 if entry=='caller_full'or not consumed else 77
     final_gp=0x41414141
    if wanted is not None:assert register_value('v0')==wanted,(entry,register_value('v0'),wanted)
    assert register_value('sp')==0x7fe0 and register_value('gp')==final_gp and register_value('ra')==0x7ff0
    for register,value in preserved:assert register_value(register)==value
    row.update(result=register_value('v0')if wanted is not None else None,source_return='int'if wanted is not None else'void',final_SP=register_value('sp'),final_GP=register_value('gp'),GP_restored=(register_value('gp')==0x41414141),completed=True)
  finally:m.close()
 r['completed']=True
except BaseException:r['failure']=traceback.format_exc()
finally:(a.out/'report.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'completed':r['completed'],'cases':len(r['cases']),'failure':r.get('failure')}))
if not r['completed']:raise SystemExit(1)
