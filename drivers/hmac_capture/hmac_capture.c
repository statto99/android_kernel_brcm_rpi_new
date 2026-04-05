#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <asm/ptrace.h>

#define TARGET_COMM "ar.tvplayer.tv"
#define ANON_SIZE   0x78000

static int fired = 0;

static int mmap_handler(struct kprobe *kp, struct pt_regs *regs)
{
    struct pt_regs *uregs;
    unsigned long len, prot, flags;

    if (strncmp(current->comm, TARGET_COMM, 14) != 0) return 0;

    uregs  = (struct pt_regs *)regs->regs[0];
    len    = uregs->regs[1];
    prot   = uregs->regs[2];
    flags  = uregs->regs[3];

    /* Log all mmaps so we can see what sizes/prots are used */
    if (fired < 30) {
        fired++;
        pr_info("hmac_capture: mmap pid=%d len=0x%lx prot=0x%lx flags=0x%lx\n",
                current->pid, len, prot, flags);
    }

    return 0;
}

static struct kprobe kp = {
    .symbol_name = "__arm64_sys_mmap",
    .pre_handler = mmap_handler,
};

static int __init hmac_capture_init(void)
{
    int ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("hmac_capture: kprobe failed %d\n", ret);
        return ret;
    }
    pr_info("hmac_capture: loaded\n");
    return 0;
}

static void __exit hmac_capture_exit(void)
{
    unregister_kprobe(&kp);
}

module_init(hmac_capture_init);
module_exit(hmac_capture_exit);
MODULE_LICENSE("GPL");
