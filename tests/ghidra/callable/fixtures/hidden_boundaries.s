.text
.p2align 2
.macro begin_subject name
.global \name
.type \name,%function
\name:
 sub sp,sp,#64
 str x19,[sp,#24]
 stp x29,x30,[sp,#48]
 add x29,sp,#48
 mov x9,x0
 mov w0,w1
.endm
.macro end_subject name
 ldr x19,[sp,#24]
 ldp x29,x30,[sp,#48]
 add sp,sp,#64
 ret
.size \name,.-\name
.endm

begin_subject hidden_local
 mov x8,sp
 blr x9
 ldr x0,[sp]
 ldr x10,[sp,#16]
 add x0,x0,x10
end_subject hidden_local

begin_subject hidden_overlap
 add x8,sp,#8
 blr x9
 ldr x0,[sp,#8]
 ldr x10,[sp,#24]
 add x0,x0,x10
end_subject hidden_overlap

begin_subject hidden_below_sp
 sub x8,sp,#32
 blr x9
 ldur x0,[sp,#-32]
 ldur x10,[sp,#-16]
 add x0,x0,x10
end_subject hidden_below_sp

begin_subject hidden_live_alias
 mov x8,sp
 mov x12,x8
 blr x9
 ldr x0,[x12]
end_subject hidden_live_alias

begin_subject hidden_explicit_alias
 mov x8,sp
 mov x1,x8
 blr x9
 ldr x0,[sp]
end_subject hidden_explicit_alias

.global make_big
.type make_big,%function
make_big:
 sxtw x10,w0
 mov x11,#7
 stp x10,x11,[x8]
 add x10,x10,#3
 str x10,[x8,#16]
 ret
.size make_big,.-make_big

.global make_big_explicit
.type make_big_explicit,%function
make_big_explicit:
 sxtw x10,w0
 mov x11,#7
 stp x10,x11,[x8]
 add x10,x10,#3
 str x10,[x8,#16]
 // Actual source argument alias is consumed, not declaration-only padding.
 str x10,[x1,#16]
 ret
.size make_big_explicit,.-make_big_explicit

.macro outer name,subject
.global \name
.type \name,%function
\name:
 stp x19,x30,[sp,#-16]!
 mov x19,#42
 bl \subject
 mov x0,x19
 ldp x19,x30,[sp],#16
 ret
.size \name,.-\name
.endm
outer outer_local,hidden_local
outer outer_overlap,hidden_overlap

.global selected_child
.type selected_child,%function
selected_child:
 stp x29,x30,[sp,#-16]!
 mov x29,sp
 adrp x9,pointer_slot
 ldr x9,[x9,:lo12:pointer_slot]
 blr x9
 ldr x0,[x0]
 ldp x29,x30,[sp],#16
 ret
.size selected_child,.-selected_child

.global native_pointer
.type native_pointer,%function
native_pointer:
 adrp x0,pointer_value
 add x0,x0,:lo12:pointer_value
 ret
.size native_pointer,.-native_pointer

.data
.p2align 3
.global pointer_slot
pointer_slot:
 .quad native_pointer
.global pointer_value
pointer_value:
 .quad 13

.text
.p2align 2
.macro mutable_subject name,slot
.global \name
.type \name,%function
\name:
 mov w1,w0
 adrp x0,\slot
 ldr x0,[x0,:lo12:\slot]
 b hidden_local
.size \name,.-\name
.endm
mutable_subject mutable_big,big_slot

.global make_big_other
.type make_big_other,%function
make_big_other:
 sxtw x10,w0
 mov x11,#7
 stp x10,x11,[x8]
 add x10,x10,#9
 str x10,[x8,#16]
 ret
.size make_big_other,.-make_big_other

.data
.p2align 3
.global big_slot
.type big_slot,%object
big_slot:
 .quad make_big
.size big_slot,8
.text
.macro spill_result name,store=1,escape=0,restore=1,reallocate=0
.global \name
.type \name,%function
\name:
 sub sp,sp,#16
 mov x1,x8
 .if \store == 1
 str w0,[sp,#12]
 .elseif \store == 2
 strh w0,[sp,#12]
 .endif
 .if \reallocate
 add sp,sp,#16
 sub sp,sp,#16
 .endif
 mov x0,#10
 .if \escape
 mov x0,sp
 .endif
 str x0,[x1]
 mov x0,#100
 str x0,[x1,#8]
 ldrsw x0,[sp,#12]
 str x0,[x1,#16]
 .if \restore
 add sp,sp,#16
 .endif
 ret
.size \name,.-\name
.endm
spill_result make_big_spill
spill_result make_big_spill_partial,2
spill_result make_big_spill_uninitialized,0
spill_result make_big_spill_escape,1,1
spill_result make_big_spill_unbalanced,1,0,0
spill_result make_big_spill_reallocated,1,0,1,1

.macro spill_consumer name,callee
.global \name
.type \name,%function
\name:
 stp x29,x30,[sp,#-48]!
 mov x29,sp
 add x8,sp,#24
 bl \callee
 ldr x0,[sp,#40]
 ldp x29,x30,[sp],#48
 ret
.size \name,.-\name
.endm
spill_consumer spill_direct,make_big_spill
spill_consumer spill_partial,make_big_spill_partial
spill_consumer spill_uninitialized,make_big_spill_uninitialized
spill_consumer spill_escape,make_big_spill_escape
spill_consumer spill_unbalanced,make_big_spill_unbalanced
spill_consumer spill_reallocated,make_big_spill_reallocated
