.text
.code32
.global call_old
.type call_old,@function
call_old:
 push %ebp
 mov %esp,%ebp
 push 12(%ebp)
 call *8(%ebp)
 leave
 ret
.size call_old,.-call_old
.global call_future
.type call_future,@function
call_future:
 push %ebp
 mov %esp,%ebp
 mov 12(%ebp),%ecx
 call *8(%ebp)
 leave
 ret
.size call_future,.-call_future
.global nested_identity
.type nested_identity,@function
nested_identity:
 mov 4(%esp),%eax
 ret
.size nested_identity,.-nested_identity
.global old_callee
.type old_callee,@function
old_callee:
 mov 4(%esp),%eax
 add $1,%eax
 ret $4
.size old_callee,.-old_callee
.global future_callee
.type future_callee,@function
future_callee:
 lea 1(%ecx),%eax
 ret
.size future_callee,.-future_callee
