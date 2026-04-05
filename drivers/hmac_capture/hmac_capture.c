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
#include <linux/ptrace.h>

#define HMAC_OFFSET 0x143ac
#define ANON_SIZE   0x78000
#define TARGET_COMM "ar.tvplayer.tv"

static uint8_t master_key[32];
static int key_captured = 0;
static unsigned long saved_x0 = 0;
static struct perf_event *bp_entry = NULL;
static struct perf_event *bp_ret = NULL;
static pid_t target_pid = 0;

/* Hardware breakpoint handler - fires at HMAC entry */
static void hmac_entry_handler(struct perf_event *bp,
                                struct perf_sample_data *data,
                                struct pt_regs *regs)
{
    char comm[TASK_COMM_LEN];
    get_task_comm(comm, current);
    if (strncmp(comm, TARGET_COMM, 14) != 0)
        return;

    saved_x0 = regs->regs[0];
    pr_info("hmac_capture: HMAC entry x0=0x%lx pid=%d\n",
            saved_x0, current->pid);
}

/* Hardware breakpoint handler - fires at HMAC return */
static void hmac_ret_handler(struct perf_event *bp,
                              struct perf_sample_data *data,
                              struct pt_regs *regs)
{
    char comm[TASK_COMM_LEN];
    get_task_comm(comm, current);
    if (strncmp(comm, TARGET_COMM, 14) != 0)
        return;
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

static int register_breakpoints(pid_t pid, unsigned long anon_base)
{
    struct perf_event_attr attr;
    unsigned long hmac_addr = anon_base + HMAC_OFFSET;
    /* HMAC function ends ~0x70 bytes after entry based on analysis */
    unsigned long hmac_ret_addr = anon_base + HMAC_OFFSET + 0x170;
    struct task_struct *task;

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (task) get_task_struct(task);
    rcu_read_unlock();

    if (!task) {
        pr_err("hmac_capture: pid %d not found\n", pid);
        return -ESRCH;
    }

    unregister_breakpoints();

    /* Entry breakpoint */
    hw_breakpoint_init(&attr);
    attr.bp_addr = hmac_addr;
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
    pr_info("hmac_capture: entry bp at 0x%lx\n", hmac_addr);

    /* Return breakpoint - find actual ret instruction offset */
    attr.bp_addr = hmac_ret_addr;
    bp_ret = register_user_hw_breakpoint(&attr, hmac_ret_handler,
                                          NULL, task);
    if (IS_ERR(bp_ret)) {
        pr_err("hmac_capture: ret bp failed %ld\n", PTR_ERR(bp_ret));
        bp_ret = NULL;
        /* Still useful with just entry bp for now */
    } else {
        pr_info("hmac_capture: ret bp at 0x%lx\n", hmac_ret_addr);
    }

    put_task_struct(task);
    return 0;
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
            pr_info("hmac_capture: anon at 0x%lx\n", base);
            break;
        }
        vma = vma->vm_next;
    }
    mmap_read_unlock(mm);
    mmput(mm);
    return base;
}

/* Write PID to /proc/hmac_capture to arm the breakpoints */
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

    pr_info("hmac_capture: arming for pid=%d\n", pid);

    anon_base = find_anon_base(pid);
    if (!anon_base) {
        pr_err("hmac_capture: anon not found for pid %d\n", pid);
        return -ENOENT;
    }

    target_pid = pid;
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
    proc_create("hmac_capture", 0666, NULL, &hmac_ops);
    pr_info("hmac_capture: ready - echo PID > /proc/hmac_capture\n");
    return 0;
}

static void __exit hmac_capture_exit(void)
{
    unregister_breakpoints();
    remove_proc_entry("hmac_capture", NULL);
}

module_init(hmac_capture_init);
module_exit(hmac_capture_exit);
MODULE_LICENSE("GPL");
