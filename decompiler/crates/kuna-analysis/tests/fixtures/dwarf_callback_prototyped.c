typedef int (*Open)();
typedef int (*Closed)(void);
typedef int (*Fixed)(int);
typedef int (*Variadic)(int, ...);

int target_open(x) int x; { return x + 1; }
int target_closed(void) { return 7; }
int target_fixed(int x) { return x + 2; }
int target_variadic(int x, ...) { return x + 3; }

Open open_slot = target_open;
Closed closed_slot = target_closed;
Fixed fixed_slot = target_fixed;
Variadic variadic_slot = target_variadic;

int invoke_open(Open callback, int value) { return callback(value); }
int invoke_closed(Closed callback) { return callback(); }
int invoke_fixed(Fixed callback, int value) { return callback(value); }
int invoke_variadic(Variadic callback, int value) { return callback(value, 3); }

int main(void) {
    return (invoke_open(open_slot, 41) != 42)
        | (invoke_closed(closed_slot) != 7)
        | (invoke_fixed(fixed_slot, 40) != 42)
        | (invoke_variadic(variadic_slot, 39) != 42);
}
