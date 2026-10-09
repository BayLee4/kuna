/* DWARF declaration donor, not the machine-behavior oracle. The reviewed builder
 * injects the original acceptance machine bodies after linking, preserving these
 * compiler-generated formal DIEs and the ELF symbol addresses. */
typedef unsigned char Flags;
typedef int (*Callback)(Flags);
#define FIXTURE __attribute__((noinline,used))
#define CAPACITY() __asm__ volatile(".rept 64\nnop\n.endr" ::: "memory")
FIXTURE int byte_target(Flags value) { CAPACITY(); return value == 85; }
FIXTURE int word_target(Flags value) { CAPACITY(); return value == 85; }
FIXTURE Callback choose(unsigned int which) { CAPACITY(); return which ? word_target : byte_target; }
FIXTURE int invoke(Flags value, Callback callback) { CAPACITY(); return callback(value); }
FIXTURE int dispatch(Flags value, unsigned int which) { CAPACITY(); return invoke(value, choose(which)); }
FIXTURE int direct_dirty(void) { CAPACITY(); return word_target((Flags)0x10055); }
FIXTURE int direct_clean(void) { CAPACITY(); return word_target(85); }
FIXTURE int ambient(void) { CAPACITY(); return word_target(0); }
FIXTURE int ambient_dirty(void) { CAPACITY(); return ambient(); }
FIXTURE int ambient_clean(void) { CAPACITY(); return ambient(); }
FIXTURE int bool_byte(_Bool value) { CAPACITY(); return value ? 1 : 0; }
FIXTURE int wide_ambient(unsigned long long bits) { CAPACITY(); return ambient() + (bits != 0); }
FIXTURE int native_register_callback(Callback callback) { CAPACITY(); return callback((Flags)0x10055); }
FIXTURE int forward(Callback callback) { CAPACITY(); return native_register_callback(callback); }
FIXTURE int carry_dispatch(unsigned long long bits, unsigned int which) { CAPACITY(); return dispatch((Flags)bits, which); }
FIXTURE int carry_invoke(unsigned long long bits, Callback callback) { CAPACITY(); return invoke((Flags)bits, callback); }
FIXTURE int carry_ambient(unsigned long long bits) { CAPACITY(); return ambient() + (bits != 0); }
FIXTURE int carry_bool(unsigned long long bits) { CAPACITY(); return bool_byte((_Bool)bits); }
