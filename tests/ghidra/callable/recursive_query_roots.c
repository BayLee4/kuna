typedef struct Node Node;
typedef Node (*Fn)(Node);
struct Node { double d; Fn next; };

__attribute__((noinline)) Fn callable_root(Fn value) {
    return value;
}

__attribute__((noinline)) Node record_root(Node value) {
    return value;
}
