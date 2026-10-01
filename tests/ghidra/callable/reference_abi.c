typedef struct Node Node;
typedef Node (*Fn)(Node);
struct Node {
    double d;
    Fn next;
};

__attribute__((noinline)) Node transform(Node node) {
    node.d += 1.0;
    return node;
}

__attribute__((noinline)) double drive(Node node, Fn callback) {
    Node result = callback(node);
    return result.d;
}

typedef struct Big24 {
    unsigned long long a;
    unsigned long long b;
    unsigned long long c;
} Big24;

__attribute__((noinline)) unsigned long long drive_big(Big24 (*callback)(int), int tag) {
    Big24 result = callback(tag);
    return result.a + result.c;
}
