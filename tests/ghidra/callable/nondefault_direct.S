.text
.code32
.p2align 4
.global caller_std
.type caller_std,@function
caller_std:
 push %ebp
 mov %esp,%ebp
 push 8(%ebp)
 call target_std
 leave
 ret
.size caller_std,.-caller_std

.p2align 4
.global target_std
.type target_std,@function
target_std:
 mov 4(%esp),%eax
 add $7,%eax
 ret $4
.size target_std,.-target_std

.p2align 4
.global caller_fast
.type caller_fast,@function
caller_fast:
 push %ebp
 mov %esp,%ebp
 mov 8(%ebp),%ecx
 call target_fast
 leave
 ret
.size caller_fast,.-caller_fast

.p2align 4
.global target_fast
.type target_fast,@function
target_fast:
 lea 7(%ecx),%eax
 ret
.size target_fast,.-target_fast

.p2align 4
.global choose_std
.type choose_std,@function
choose_std:
 mov $target_std,%eax
 ret
.size choose_std,.-choose_std

.p2align 4
.global nested_identity
.type nested_identity,@function
nested_identity:
 mov 4(%esp),%eax
 ret
.size nested_identity,.-nested_identity
