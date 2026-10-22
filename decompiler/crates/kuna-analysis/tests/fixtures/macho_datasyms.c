int exported_count = 7;
int exported_table[3] = {1, 2, 3};
static volatile int local_total = 5;
int zeroed[4];
int main(void) { return exported_count + exported_table[1] + local_total + zeroed[2]; }
