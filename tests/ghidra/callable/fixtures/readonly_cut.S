#ifndef FLAG_VALUE
#define FLAG_VALUE 0
#endif

.text
.p2align 4
.global subject
.type subject,@function
subject:
 cmpb $0,flag(%rip)
 je .Lpreserved
 mov $7,%ebx
.Lpreserved:
 mov $11,%eax
 ret
.size subject,.-subject

.p2align 4
.global outer
.type outer,@function
outer:
 push %rbx
 mov $42,%ebx
 call subject
 mov %rbx,%rax
 pop %rbx
 ret
.size outer,.-outer

#ifdef MUTABLE_FLAG
.data
#else
.section .rodata
#endif
.global flag
.type flag,@object
flag:
 .byte FLAG_VALUE
.size flag,.-flag
