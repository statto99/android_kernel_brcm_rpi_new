#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/kprobes.h>

#define TARGET_COMM "ar.tvplayer.tv"

static int fired = 0;

static int mmap_handler(struct kprobe *kp, struct pt_regs *regs)
{
    if (fired > 10) return 0;
    if (strncmp(current->comm, TARGET_COMM, 14) != 0) return 0;
    fired++;
    pr_info("hmac_capture: mmap comm=%s pid=%d\n",
            current->comm, current->pid);
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
