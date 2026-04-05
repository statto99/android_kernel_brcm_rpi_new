#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/pid.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/kprobes.h>
#include <linux/workqueue.h>
#include <asm/ptrace.h>

#define HMAC_ENTRY  0x143ac
#define ANON_SIZE   0x78000
#define TARGET_COMM "ar.tvplayer.tv"

static uint8_t master_key[32];
static int key_captured = 0;
static unsigned long saved_x0 = 0;
static struct perf_event *bp_entry = NULL;
static struct perf_event *bp_ret = NULL;
static struct work_struct arm_work;
static unsigned long pending_anon_base = 0;
static pid_t pending_pid = 0;

static void unregister_breakpoints(void)
{
    if (bp_entry) {
        unregister_hw_breakpoint(bp_entry);
        bp_entry = NULL;
    }
    if (bp_ret) {
        unregister_hw_breakpoint(bp_ret);
        bp_ret = NULL;
    }
}

static void hmac_ret_handler(struct perf_event *bp,
                              struct perf_sample_data *data,
                              struct pt_regs *regs)
{
    if (strncmp(current->comm, TARGET_COMM, 14) != 0) return;
    if (!saved_x0) return;

    pr_info("hmac_capture: watchpoint fired reading from 0x%lx\n", saved_x0);

    if (copy_from_user(master_key, (void __user *)saved_x0, 32) == 0) {
        key_captured = 1;
        pr_info("hmac_capture: MASTER KEY: "
                "%02x%02x%02x%02x%02x%02x%02x%02x"
                "%02x%02x%02x%02x%02x%02x%02x%02x"
                "%02x%02x%02x%02x%02x%02x%02x%02x"
                "%02x%02x%02x%02x%02x%02x%02x%02x\n",
                master_key[0],master_key[1],master_key[2],master_key[3],
                master_key[4],master_key[5],master_key[6],master_key[7],
                master_key[8],master_key[9],master_key[10],master_key[11],
                master_key[12],master_key[13],master_key[14],master_key[15],
                master_key[16],master_key[17],master_key[18],master_key[19],
                master_key[20],master_key[21],master_key[22],master_key[23],
                master_key[24],master_key[25],master_key[26],master_key[27],
                master_key[28],master_key[29],master_key[30],master_key[31]);
    } else {
        pr_err("hmac_capture: copy_from_user failed addr=0x%lx\n", saved_x0);
    }
    saved_x0 = 0;
}

static void hmac_entry_handler(struct perf_event *bp,
                                struct perf_sample_data *data,
                                struct pt_regs *regs)
{
    struct perf_event_attr wattr;

    if (strncmp(current->comm, TARGET_COMM, 14) != 0) return;
    if (saved_x0) return;

    saved_x0 = regs->regs[0];
    pr_info("hmac_capture: HMAC entry x0=0x%lx pid=%d\n",
            saved_x0, current->pid);

    /* Replace ret bp with write watchpoint on last 4 bytes of output buffer */
    if (bp_ret) {
        unregister_hw_breakpoint(bp_ret);
        bp_ret = NULL;
    }

    hw_breakpoint_init(&wattr);
    wattr.bp_addr = saved_x0 + 28;
    wattr.bp_len  = HW_BREAKPOINT_LEN_4;
    wattr.bp_type = HW_BREAKPOINT_W;

    bp_ret = register_user_hw_breakpoint(&wattr, hmac_ret_handler,
                                          NULL, current);
    if (IS_ERR(bp_ret)) {
        pr_err("hmac_capture: watchpoint failed %ld\n", PTR_ERR(bp_ret));
        bp_ret = NULL;
    } else {
        pr_info("hmac_capture: watchpoint at 0x%lx\n", saved_x0 + 28);
    }
}

static void arm_work_fn(struct work_struct *work)
{
    struct perf_event_attr attr;
    struct task_struct *task;
    unsigned long anon_base = pending_anon_base;
    pid_t pid = pending_pid;

    if (!anon_base || !pid) return;

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (task) get_task_struct(task);
    rcu_read_unlock();

    if (!task) {
        pr_err("hmac_capture: task not found pid=%d\n", pid);
        return;
    }

    unregister_breakpoints();

    hw_breakpoint_init(&attr);
    attr.bp_addr = anon_base + HMAC_ENTRY;
    attr.bp_len  = HW_BREAKPOINT_LEN_4;
    attr.bp_type = HW_BREAKPOINT_X;

    bp_entry = register_user_hw_breakpoint(&attr, hmac_entry_handler,
                                            NULL, task);
    if (IS_ERR(bp_entry)) {
        pr_err("hmac_capture: entry bp failed %ld\n", PTR_ERR(bp_entry));
        bp_entry = NULL;
        put_task_struct(task);
        return;
    }
    pr_info("hmac_capture: entry bp OK at 0x%lx\n", anon_base + HMAC_ENTRY);
    pr_info("hmac_capture: armed pid=%d anon=0x%lx\n", pid, anon_base);

    put_task_struct(task);
    pending_anon_base = 0;
    pending_pid = 0;
}

static int mprotect_handler(struct kprobe *kp, struct pt_regs *regs)
{
    struct pt_regs *uregs;
    u64 len, prot, addr;

    if (strncmp(current->comm, TARGET_COMM, 14) != 0) return 0;
    if (bp_entry) return 0;
    if (pending_pid) return 0;

    uregs = (struct pt_regs *)regs->regs[0];
    addr  = uregs->regs[0];
    len   = uregs->regs[1];
    prot  = uregs->regs[2];

    if (len == ANON_SIZE && (prot & 0x4)) {
        pr_info("hmac_capture: anon mprotect pid=%d addr=0x%llx\n",
                current->pid, addr);
        pending_anon_base = (unsigned long)addr;
        pending_pid = current->pid;
        schedule_work(&arm_work);
    }

    return 0;
}

static struct kprobe kp = {
    .symbol_name = "__arm64_sys_mprotect",
    .pre_handler = mprotect_handler,
};

static int hmac_show(struct seq_file *m, void *v)
{
    int i;
    if (key_captured) {
        seq_printf(m, "KEY: ");
        for (i = 0; i < 32; i++)
            seq_printf(m, "%02x", master_key[i]);
        seq_printf(m, "\n");
    } else {
        seq_printf(m, "NO KEY\n");
    }
    return 0;
}

static int hmac_open(struct inode *inode, struct file *file)
{
    return single_open(file, hmac_show, NULL);
}

static const struct proc_ops hmac_ops = {
    .proc_open    = hmac_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

static int __init hmac_capture_init(void)
{
    int ret;

    INIT_WORK(&arm_work, arm_work_fn);

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("hmac_capture: kprobe failed %d\n", ret);
        return ret;
    }

    proc_create("hmac_capture", 0444, NULL, &hmac_ops);
    pr_info("hmac_capture: loaded watching for %s\n", TARGET_COMM);
    return 0;
}

static void __exit hmac_capture_exit(void)
{
    cancel_work_sync(&arm_work);
    unregister_kprobe(&kp);
    unregister_breakpoints();
    remove_proc_entry("hmac_capture", NULL);
}

module_init(hmac_capture_init);
module_exit(hmac_capture_exit);
MODULE_LICENSE("GPL");
