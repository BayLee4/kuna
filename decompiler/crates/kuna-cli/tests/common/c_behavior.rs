use std::path::Path;

pub fn assert_three_call_chain(source: &Path, body: &str, function: &str) {
    let preamble = r#"
static unsigned order[4], count;
static void record(unsigned id) {
    if (count < 4) order[count] = id;
    ++count;
}
static void first(void) { record(1); }
static void second(void) { record(2); }
static void third(void) { record(3); }
void (*dat_804a000)(void) = first;
void (*dat_804a004)(void) = second;
void (*dat_804a008)(void) = third;
"#;
    let driver = format!(
        r#"
int main(void) {{
    for (unsigned run = 0; run < 2; ++run) {{
        count = 0;
        {function}();
        if (count != 3 || order[0] != 1 || order[1] != 2 || order[2] != 3) return 1;
    }}
    return 0;
}}
"#
    );
    kuna_harness::c_behavior::assert_c_behavior(source, preamble, body, &driver);
}
