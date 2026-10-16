/* Real declaration facts; compile with C89 and C11, -g -O0. */
typedef int (*Open)();
typedef int (*Closed)(void);
typedef int (*Fixed)(int);
typedef int (*Variadic)(int, ...);
typedef unsigned char Flags;
typedef int (*FlagCallback)(Flags, signed char);
typedef void (*NoReturn)(void) __attribute__((noreturn));
typedef struct Node Node;
struct Node { Node *next; void (*visit)(Node *); };
typedef enum Mode { Seven = 7, Negative = -1 } Mode;
typedef struct { unsigned char op; unsigned short val; } code;
struct Forward;
typedef struct Forward ForwardAlias;
volatile int object_volatile;
volatile int *pointee_volatile;
int *volatile pointer_volatile;
Fixed callback_global;
const char *const default_authors[3] = { "ada", "grace", "edsger" };

int target_open(x) int x; { return x + 1; }
int target_closed(void) { return 41; }
int target_fixed(int x) { return x + 1; }
int target_variadic(int x, ...) {
    __builtin_va_list ap;
    int tail;
    __builtin_va_start(ap, x);
    tail = __builtin_va_arg(ap, int);
    __builtin_va_end(ap);
    return x + tail;
}
int invoke_open(Open callback, int x) { return callback(x); }
int invoke_closed(Closed callback) { return callback(); }
int invoke_fixed(Fixed callback, int x) { return callback(x); }
int invoke_variadic(Variadic callback, int x) { return callback(x, 58); }
int invoke_flags(Flags value, FlagCallback callback) { return callback(value, -1); }
void invoke_noreturn(NoReturn callback) { callback(); }
unsigned char unsigned_identity(unsigned char value) { return value; }
signed char signed_identity(signed char value) { return value; }
char plain_identity(char value) { return value; }
Node *node_identity(Node *value) { return value; }
Mode mode_identity(Mode value) { return value; }
int walk_source_codes(code *base, int n) {
    int total = 0;
    while (n-- > 0) { total += base->val; ++base; }
    return total;
}
int consume_forward(ForwardAlias *value, int count) { return value ? count : 0; }
int read_object_twice(void) { return object_volatile + object_volatile; }
int read_pointer_twice(void) { return *pointer_volatile + *pointer_volatile; }
int read_pointee_twice(void) { return *pointee_volatile + *pointee_volatile; }
int main(void) { return 0; }
