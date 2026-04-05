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
#include <linux/delay.h>
#include <linux/workqueue.h>

#define HMAC_ENTRY  0x143ac
#define HMAC_RET    0x1451c
#define ANON_SIZE   0x78000
#define TARGET_COMM "ar.tvplayer.tv"

static uint8_t master_key[32];
static int key_captured = 0;
static unsigned long saved_x0 = 0;
static struct perf_event *bp_entry = NULL;
static struct perf_event *bp_ret = NULL;
static struct delayed_work arm_work;
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

static void hmac_entry_handler(struct perf_event *bp,
                                struct perf_sample_data *data,
                                struct pt_regs *regs)
{
    char comm[TASK_COMM_LEN];
    get_task_comm(comm, current);
    if (strncmp(comm, TARGET_COMM, 14) != 0) return;
    saved_x0 = regs->regs[0];
    pr_info("hmac_capture: HMAC entry x0=0x%lx pid=%d\n",
            saved_x0, current->pid);
}

static void hmac_ret_handler(struct perf_event *bp,
                              struct perf_sample_data *data,
                              struct pt_regs *regs)
{
    char comm[TASK_COMM_LEN];
    get_task_comm(comm, current);
    if (strncmp(comm, TARGET_COMM, 14) != 0) return;
    if (!saved_x0) return;

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
        pr_err("hmac_capture: copy_from_user failed\n");
    }
    saved_x0 = 0;
}

static unsigned long find_anon_base(pid_t pid)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    unsigned long base = 0;

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (task) get_task_struct(task);
    rcu_read_unlock();
    if (!task) return 0;

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) return 0;

    mmap_read_lock(mm);
    vma = mm->mmap;
    while (vma) {
        unsigned long size = vma->vm_end - vma->vm_start;
        if (size == ANON_SIZE &&
            (vma->vm_flags & VM_EXEC) &&
            (vma->vm_flags & VM_READ) &&
            !(vma->vm_flags & VM_WRITE) &&
            !vma->vm_file) {
            base = vma->vm_start;
            break;
        }
        vma = vma->vm_next;
    }
    mmap_read_unlock(mm);
    mmput(mm);
    return base;
}

static int register_breakpoints(pid_t pid, unsigned long anon_base)
{
    struct perf_event_attr attr;
    struct task_struct *task;

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (task) get_task_struct(task);
    rcu_read_unlock();
    if (!task) return -ESRCH;

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
        return -1;
    }

    attr.bp_addr = anon_base + HMAC_RET;
    bp_ret = register_user_hw_breakpoint(&attr, hmac_ret_handler,
                                          NULL, task);
    if (IS_ERR(bp_ret)) {
        pr_err("hmac_capture: ret bp failed %ld\n", PTR_ERR(bp_ret));
        bp_ret = NULL;
    }

    pr_info("hmac_capture: armed pid=%d anon=0x%lx entry=0x%lx ret=0x%lx\n",
            pid, anon_base,
            anon_base + HMAC_ENTRY,
            anon_base + HMAC_RET);

    put_task_struct(task);
    return 0;
}

/* Workqueue function - polls for anon segment after exec */
static void arm_work_fn(struct work_struct *work)
{
    unsigned long anon_base;
    int retries = 0;

    if (!pending_pid) return;

    /* Poll for anon segment - it gets mapped during JNI_OnLoad */
    while (retries < 50) {
        anon_base = find_anon_base(pending_pid);
        if (anon_base) {
            pr_info("hmac_capture: found anon=0x%lx after %d retries\n",
                    anon_base, retries);
            register_breakpoints(pending_pid, anon_base);
            pending_pid = 0;
            return;
        }
        msleep(100);
        retries++;
    }
    pr_err("hmac_capture: anon not found for pid=%d\n", pending_pid);
    pending_pid = 0;
}

/* Kprobe on wake_up_new_task to detect new processes */
static int wake_up_handler(struct kprobe *kp, struct pt_regs *regs)
{
    struct task_struct *task = (struct task_struct *)regs->regs[0];
    if (!task) return 0;

    /* Check if this is TiviMate */
    if (strncmp(task->comm, TARGET_COMM, 14) == 0) {
        pr_info("hmac_capture: detected %s pid=%d\n",
                task->comm, task->pid);
        pending_pid = task->pid;
        schedule_delayed_work(&arm_work, msecs_to_jiffies(500));
    }
    return 0;
}

static struct kprobe kp = {
    .symbol_name = "wake_up_new_task",
    .pre_handler = wake_up_handler,
};

/* Manual trigger via /proc */
static ssize_t hmac_write(struct file *file, const char __user *ubuf,
                           size_t count, loff_t *ppos)
{
    char buf[16];
    pid_t pid;
    unsigned long anon_base;

    if (count > 15) return -EINVAL;
    if (copy_from_user(buf, ubuf, count)) return -EFAULT;
    buf[count] = 0;
    if (kstrtoint(buf, 10, &pid)) return -EINVAL;

    anon_base = find_anon_base(pid);
    if (!anon_base) {
        pr_err("hmac_capture: anon not found for pid=%d\n", pid);
        return -ENOENT;
    }
    register_breakpoints(pid, anon_base);
    return count;
}

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
    .proc_write   = hmac_write,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

static int __init hmac_capture_init(void)
{
    int ret;

    INIT_DELAYED_WORK(&arm_work, arm_work_fn);

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("hmac_capture: kprobe failed %d\n", ret);
        return ret;
    }

    proc_create("hmac_capture", 0666, NULL, &hmac_ops);
    pr_info("hmac_capture: loaded - watching for %s\n", TARGET_COMM);
    return 0;
}

static void __exit hmac_capture_exit(void)
{
    cancel_delayed_work_sync(&arm_work);
    unregister_kprobe(&kp);
    unregister_breakpoints();
    remove_proc_entry("hmac_capture", NULL);
}

module_init(hmac_capture_init);
module_exit(hmac_capture_exit);
MODULE_LICENSE("GPL");
