typedef int (*Fn)(int);
#define NOINLINE __attribute__((noinline))
extern Fn returned_scalar_child(int value);
extern int scalar_root(Fn callback, int value);
extern int actual_leaf(int value);

NOINLINE int scalar_entry(int value) { return scalar_root(actual_leaf, value); }

NOINLINE Fn returned_scalar_root(int value) { return returned_scalar_child(value); }
NOINLINE int returned_scalar_consumer(int value) {
    Fn callback = returned_scalar_root(value);
    return callback(value);
}
