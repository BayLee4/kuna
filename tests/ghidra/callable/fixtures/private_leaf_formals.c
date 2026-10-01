/* Compiler-generated declaration donor; the builder installs the reviewed
 * original machine bodies without modifying these authentic DWARF sections. */
typedef unsigned long long Word;
#define FIXTURE __attribute__((noinline,used))
#define CAPACITY() __asm__ volatile(".rept 64\nnop\n.endr" ::: "memory")
FIXTURE void subject(Word *slot) { CAPACITY(); *slot = 7; }
FIXTURE Word dispatch(Word *slot) { CAPACITY(); subject(slot); return 42; }
