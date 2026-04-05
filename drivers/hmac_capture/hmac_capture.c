#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <asm/ptrace.h>

#define TARGET_COMM "ar.tvplayer.tv"
#define ANON_SIZE   0x78000

static int mprotect_handler(struct kprobe *kp, struct pt_regs *regs)
{
    struct pt_regs *uregs;
    u64 len, prot, addr;

    if (strncmp(current->comm, TARGET_COMM, 14) != 0) return 0;

    uregs = (struct pt_regs *)regs->regs[0];
    addr  = uregs->regs[0];
    len   = uregs->regs[1];
    prot  = uregs->regs[2];

    if (len == ANON_SIZE && (prot & 0x4)) {
        pr_info("hmac_capture: ANON mprotect pid=%d len=0x%llx prot=0x%llx addr=0x%llx\n",
                current->pid, len, prot, addr);
    }

    return 0;
}

static struct kprobe kp = {
    .symbol_name = "__arm64_sys_mprotect",
    .pre_handler = mprotect_handler,
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
