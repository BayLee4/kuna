/* Execution-only input. The original default_authors[3] stays unterminated. */
#ifndef KUNA_EMITTED_DRIVER
#define main retained_unterminated_main
#include "typedepth_x86_64.c"
#undef main
#endif

int main(void)
{
    const char *const execution_authors[4] = { "ada", "grace", "edsger", 0 };
    return count_authors(execution_authors) != 14;
}
