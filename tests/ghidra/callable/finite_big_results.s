.text
.p2align 2
.macro CALLER_BEGIN name
.global \name
.type \name,%function
\name:
 sub sp,sp,#48
 stp x29,x30,[sp,#32]
 mov x29,sp
.endm
.macro CALLER_END name
 add x8,sp,#8
 blr x16
 ldr x0,[sp,#8]
 ldr x9,[sp,#24]
 add x0,x0,x9
 ldp x29,x30,[sp,#32]
 add sp,sp,#48
 ret
.size \name,.-\name
.global \name\()_end
\name\()_end:
.endm

CALLER_BEGIN finite_static
 adrp x16,make_big_a
 add x16,x16,:lo12:make_big_a
CALLER_END finite_static

CALLER_BEGIN finite_phi
 cbz w1,.Luse_a
 adrp x16,make_big_b
 add x16,x16,:lo12:make_big_b
 b .Lselected
.Luse_a:
 adrp x16,make_big_a
 add x16,x16,:lo12:make_big_a
.Lselected:
CALLER_END finite_phi

.global make_big_a
.type make_big_a,%function
make_big_a:
 sxtw x10,w0
 mov x11,#7
 stp x10,x11,[x8]
 add x10,x10,#3
 str x10,[x8,#16]
 ret
.size make_big_a,.-make_big_a
.global make_big_a_end
make_big_a_end:

.global make_big_b
.type make_big_b,%function
make_big_b:
 sxtw x10,w0
 add x10,x10,#10
 mov x11,#11
 stp x10,x11,[x8]
 add x10,x10,#10
 str x10,[x8,#16]
 ret
.size make_big_b,.-make_big_b
.global make_big_b_end
make_big_b_end:

.macro NEGATIVE_CALLER name,target
CALLER_BEGIN \name
 adrp x16,\target
 add x16,x16,:lo12:\target
CALLER_END \name
.endm

.macro RESULT_BODY name
.global \name
.type \name,%function
\name:
 sxtw x10,w0
 mov x11,#7
 stp x10,x11,[x8]
 add x10,x10,#3
 str x10,[x8,#16]
.endm

NEGATIVE_CALLER wrong_return,wrong_return_target
NEGATIVE_CALLER mixed_return,mixed_return_target
NEGATIVE_CALLER observed_link,observed_link_target
NEGATIVE_CALLER overwritten_link,overwritten_link_target

RESULT_BODY wrong_return_target
 ret x19
.size wrong_return_target,.-wrong_return_target

RESULT_BODY mixed_return_target
 cbz w0,.Lbad_return
 ret
.Lbad_return:
 mov x9,xzr
 ret x9
.size mixed_return_target,.-mixed_return_target

RESULT_BODY observed_link_target
 str x30,[x8,#16]
 ret
.size observed_link_target,.-observed_link_target

RESULT_BODY overwritten_link_target
 add x30,x30,#4
 ret
.size overwritten_link_target,.-overwritten_link_target
