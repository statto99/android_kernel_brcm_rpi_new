#include <linux/init.h>

char *kpatch_superkey = "Test1234"; // Your password
int kpatch_has_key = 1;

// This stops the "PC : kpatch_has_key+0x0/0x8" crash
void kpatch_hook_exec(void *bprm) {
    return;
}
