#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/workqueue.h>

#define TARGET_COMM "ar.tvplayer.tv"

static int mmap_handler(struct kprobe *kp, struct pt_regs *regs)
{
    pr_info("hmac_capture: mmap called comm=%s pid=%d\n",
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
    pr_info("hmac_capture: loaded kprobe on %s\n", kp.symbol_name);
    return 0;
}

static void __exit hmac_capture_exit(void)
{
    unregister_kprobe(&kp);
    pr_info("hmac_capture: unloaded\n");
}

module_init(hmac_capture_init);
module_exit(hmac_capture_exit);
MODULE_LICENSE("GPL");
