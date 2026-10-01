.set noreorder
.set noat
.option pic0
.text

.macro ROOT_BEGIN name
.globl \name
.type \name,@function
\name:
 addiu $sp,$sp,-32
 sw $ra,28($sp)
 sw $gp,24($sp)
 lui $gp,%hi(primary_value)
 addiu $gp,$gp,%lo(primary_value)
 lui $t0,%hi(first_slot)
 lw $t9,%lo(first_slot)($t0)
 jalr $t9
 nop
.endm

.macro SECOND_CALL
 lui $t0,%hi(second_slot)
 lw $t9,%lo(second_slot)($t0)
 jalr $t9
 nop
.endm

.macro ROOT_END name
 lw $gp,24($sp)
 lw $ra,28($sp)
 addiu $sp,$sp,32
 jr $ra
 nop
.size \name,.-\name
.endm

ROOT_BEGIN caller_dirty
.globl dirty_second_call
 dirty_second_call:
 SECOND_CALL
ROOT_END caller_dirty

ROOT_BEGIN caller_full
 lui $gp,%hi(primary_value)
 addiu $gp,$gp,%lo(primary_value)
.globl full_second_call
 full_second_call:
 SECOND_CALL
ROOT_END caller_full

ROOT_BEGIN caller_partial
 lui $t0,%hi(partial_word)
 addiu $t0,$t0,%lo(partial_word)
.globl partial_merge
 partial_merge:
 lwr $gp,3($t0)
.globl partial_second_call
 partial_second_call:
 SECOND_CALL
ROOT_END caller_partial

ROOT_BEGIN caller_removed
 lui $t0,%hi(readonly_flag)
 lbu $t0,%lo(readonly_flag)($t0)
 beq $t0,$zero,removed_return
 addiu $v0,$zero,11
.globl removed_second_call
 removed_second_call:
 SECOND_CALL
removed_return:
ROOT_END caller_removed

.globl dirty_gp
.type dirty_gp,@function
dirty_gp:
 lui $gp,%hi(alternate_value)
 addiu $gp,$gp,%lo(alternate_value)
 jr $ra
 addiu $v0,$zero,0
.size dirty_gp,.-dirty_gp

.globl consume_gp
.type consume_gp,@function
consume_gp:
 lw $v0,0($gp)
 jr $ra
 nop
.size consume_gp,.-consume_gp

.globl direct_gp_parent
.type direct_gp_parent,@function
direct_gp_parent:
 addiu $sp,$sp,-32
 sw $ra,28($sp)
 jal dirty_gp
 nop
 addiu $v0,$zero,11
 lw $ra,28($sp)
 addiu $sp,$sp,32
 jr $ra
 nop
.size direct_gp_parent,.-direct_gp_parent
.globl direct_gp_parent_end
direct_gp_parent_end:

.globl direct_gp_read_parent
.type direct_gp_read_parent,@function
direct_gp_read_parent:
 addiu $sp,$sp,-32
 sw $ra,28($sp)
 jal dirty_gp
 nop
 lw $v0,0($gp)
 lw $ra,28($sp)
 addiu $sp,$sp,32
 jr $ra
 nop
.size direct_gp_read_parent,.-direct_gp_read_parent
.globl direct_gp_read_parent_end
direct_gp_read_parent_end:

.globl private_gp_spill
.type private_gp_spill,@function
private_gp_spill:
 addiu $sp,$sp,-16
 lui $gp,%hi(alternate_value)
 addiu $gp,$gp,%lo(alternate_value)
 sw $gp,8($sp)
 addiu $v0,$zero,11
 addiu $sp,$sp,16
 jr $ra
 nop
.size private_gp_spill,.-private_gp_spill
.globl private_gp_spill_end
private_gp_spill_end:

.globl private_gp_reload
.type private_gp_reload,@function
private_gp_reload:
 addiu $sp,$sp,-16
 lui $gp,%hi(alternate_value)
 addiu $gp,$gp,%lo(alternate_value)
 sw $gp,8($sp)
 lw $v0,8($sp)
 addiu $sp,$sp,16
 jr $ra
 nop
.size private_gp_reload,.-private_gp_reload
.globl private_gp_reload_end
private_gp_reload_end:

.globl private_gp_escape
.type private_gp_escape,@function
private_gp_escape:
 addiu $sp,$sp,-16
 lui $gp,%hi(alternate_value)
 addiu $gp,$gp,%lo(alternate_value)
 sw $gp,8($sp)
 addiu $t0,$sp,8
 lui $t1,%hi(escaped_slot)
 sw $t0,%lo(escaped_slot)($t1)
 addiu $sp,$sp,16
 jr $ra
 nop
.size private_gp_escape,.-private_gp_escape
.globl private_gp_escape_end
private_gp_escape_end:

.globl dirty_gp_natural
.type dirty_gp_natural,@function
dirty_gp_natural:
 lui $gp,%hi(alternate_value)
 addiu $gp,$gp,%lo(alternate_value)
 addiu $v0,$zero,0
 jr $ra
 nop
.size dirty_gp_natural,.-dirty_gp_natural
.globl dirty_gp_natural_end
dirty_gp_natural_end:

.globl direct_gp_natural_parent
.type direct_gp_natural_parent,@function
direct_gp_natural_parent:
 addiu $sp,$sp,-32
 sw $ra,28($sp)
 jal dirty_gp_natural
 nop
 addiu $v0,$zero,11
 lw $ra,28($sp)
 addiu $sp,$sp,32
 jr $ra
 nop
.size direct_gp_natural_parent,.-direct_gp_natural_parent
.globl direct_gp_natural_parent_end
direct_gp_natural_parent_end:

.section .rodata,"a",@progbits
.globl readonly_flag
.type readonly_flag,@object
readonly_flag:
.byte READONLY_VALUE
.size readonly_flag,.-readonly_flag

.data
.p2align 8
.globl primary_value
.type primary_value,@object
primary_value:
.word 11
.size primary_value,.-primary_value
.p2align 8
.globl alternate_value
.type alternate_value,@object
alternate_value:
.word 77
.size alternate_value,.-alternate_value
.globl partial_word
.type partial_word,@object
partial_word:
.word 0
.size partial_word,.-partial_word
.globl first_slot
.type first_slot,@object
first_slot:
.word dirty_gp
.size first_slot,.-first_slot
.globl second_slot
.type second_slot,@object
second_slot:
.word consume_gp
.size second_slot,.-second_slot
.globl escaped_slot
.type escaped_slot,@object
escaped_slot:
.word 0
.size escaped_slot,.-escaped_slot
