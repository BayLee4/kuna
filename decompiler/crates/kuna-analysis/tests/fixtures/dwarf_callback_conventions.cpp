struct Widget { int value; int method(int x); };
int Widget::method(int x) { return value + x; }

typedef int (*Empty)();
typedef int (*Fixed)(int);
typedef int (*Variadic)(int, ...);
typedef int (__attribute__((cdecl)) *Cdecl)(int);
typedef int (__attribute__((stdcall)) *Stdcall)(int);
typedef int (__attribute__((fastcall)) *Fastcall)(int);
typedef int (__attribute__((thiscall)) *Thiscall)(Widget *, int);

int target_empty() { return 7; }
int target_fixed(int x) { return x + 2; }
int target_variadic(int x, ...) { return x + 3; }
int __attribute__((cdecl)) target_cdecl(int x) { return x + 1; }
int __attribute__((stdcall)) target_stdcall(int x) { return x + 1; }
int __attribute__((fastcall)) target_fastcall(int x) { return x + 1; }
int __attribute__((thiscall)) target_thiscall(Widget *w, int x) { return w->value + x; }

Empty empty_slot = target_empty;
Fixed fixed_slot = target_fixed;
Variadic variadic_slot = target_variadic;
Cdecl cdecl_slot = target_cdecl;
Stdcall stdcall_slot = target_stdcall;
Fastcall fastcall_slot = target_fastcall;
Thiscall thiscall_slot = target_thiscall;

extern "C" int invoke_empty(Empty callback) { return callback(); }
extern "C" int invoke_fixed(Fixed callback, int x) { return callback(x); }
extern "C" int invoke_variadic(Variadic callback, int x) { return callback(x, 3); }
extern "C" int invoke_cdecl(Cdecl callback, int x) { return callback(x); }
extern "C" int invoke_stdcall(Stdcall callback, int x) { return callback(x); }
extern "C" int invoke_fastcall(Fastcall callback, int x) { return callback(x); }
extern "C" int invoke_thiscall(Thiscall callback, Widget *w, int x) { return callback(w, x); }
extern "C" int invoke_member(Widget *w, int x) { return w->method(x); }
