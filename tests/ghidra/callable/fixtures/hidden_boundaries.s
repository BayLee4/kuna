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

begin_subject hidden_raw_child
 mov x8,sp
 mov x19,x8
 blr x9
 mov x8,x19
 bl raw_child
end_subject hidden_raw_child

begin_subject explicit_pointer
 mov w1,w0
 mov x0,sp
 blr x9
 ldr x0,[sp]
end_subject explicit_pointer

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

.global write_big
.type write_big,%function
write_big:
 sxtw x10,w1
 mov x11,#7
 stp x10,x11,[x0]
 add x10,x10,#3
 str x10,[x0,#16]
 ret
.size write_big,.-write_big

.global raw_child
.type raw_child,%function
raw_child:
 ldr x0,[x8]
 ret
.size raw_child,.-raw_child

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

// Exact candidate for original-raw versus conditionally-selected child reads.
.global hidden_selected_child
.type hidden_selected_child,%function
hidden_selected_child:
 sub sp,sp,#64
 str x19,[sp,#24]
 stp x29,x30,[sp,#48]
 add x29,sp,#48
 mov x9,x0
 mov x8,sp
 mov x0,x8
 blr x9
 bl selected_child
end_subject hidden_selected_child

.global make_big_zero
.type make_big_zero,%function
make_big_zero:
 mov x10,#5
 mov x11,#7
 stp x10,x11,[x8]
 mov x10,#8
 str x10,[x8,#16]
 ret
.size make_big_zero,.-make_big_zero

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
