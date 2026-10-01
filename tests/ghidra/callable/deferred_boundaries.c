typedef int (*Fn)(int);
typedef Fn (*Chooser)(void);
#define NOINLINE __attribute__((noinline))

NOINLINE int actual_leaf(int value) { return 2 * value + 1; }
NOINLINE int scalar_child(Fn callback, int value) { return callback(value) + 3; }
NOINLINE int scalar_root(Fn callback, int value) { return scalar_child(callback, value) + 5; }

Fn volatile scalar_slot = actual_leaf;
NOINLINE int scalar_only_child(int value) { return scalar_slot(value) + 3; }
NOINLINE int scalar_only_root(int value) { return scalar_only_child(value) + 5; }

NOINLINE Fn actual_chooser(void) { return actual_leaf; }
NOINLINE Fn returned_child(Chooser chooser) { return chooser(); }
NOINLINE Fn returned_root(Chooser chooser) { return returned_child(chooser); }
NOINLINE int returned_consumer(Chooser chooser, int value) {
    Fn callback = returned_root(chooser);
    return callback(value);
}

NOINLINE int deferred_cycle_b(int depth, Fn callback);
NOINLINE int deferred_cycle_a(int depth, Fn callback) {
    if (depth == 0) return callback(5);
    return deferred_cycle_b(depth - 1, callback) + 1;
}
NOINLINE int deferred_cycle_b(int depth, Fn callback) {
    if (depth == 0) return callback(5);
    return deferred_cycle_a(depth - 1, callback) + 1;
}

NOINLINE int ordinary_cycle_b(int depth);
NOINLINE int ordinary_cycle_a(int depth) {
    if (depth == 0) return 11;
    return ordinary_cycle_b(depth - 1) + 1;
}
NOINLINE int ordinary_cycle_b(int depth) {
    if (depth == 0) return 11;
    return ordinary_cycle_a(depth - 1) + 1;
}

NOINLINE Fn returned_scalar_child(int value) {
    scalar_slot(value);
    return actual_leaf;
}
NOINLINE int scalar_cycle_b(int depth);
NOINLINE int scalar_cycle_a(int depth) {
    if (depth == 0) return scalar_slot(5);
    return scalar_cycle_b(depth - 1) + 1;
}
NOINLINE int scalar_cycle_b(int depth) {
    if (depth == 0) return scalar_slot(5);
    return scalar_cycle_a(depth - 1) + 1;
}
