#pragma GCC optimize ("-fno-pic")
#pragma GCC optimize ("-fno-plt")

#include <linux/kernel.h>
#include <linux/init.h>

// 1. The SuperKey: The password the Android App looks for
char *kpatch_key = "Test1234";

// 2. Declaration of the APatch binary function we created in YAML
extern void kpimg_main(void);

// 3. The function main.c is looking for (kpatch_init)
void __init kpatch_init(void) {
    printk(KERN_INFO "APatch: Initializing Kernel Patch...\n");
    kpimg_main(); // This jumps into the APatch binary
}

// 4. The Safety Hook to prevent "Attempted to kill init"
void kpatch_hook_exec(void *bprm) {
    return; 
}
