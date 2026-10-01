typedef struct State {
    unsigned long long count;
    int delta;
    int reserved;
} State;

State state = {17, 3, 0};
__attribute__((noinline)) unsigned long long read_state(void) {
    return state.count + state.delta;
}

__attribute__((noinline)) State *state_address(void) {
    return &state;
}
