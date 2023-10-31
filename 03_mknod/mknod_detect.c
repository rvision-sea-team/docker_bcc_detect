#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/socket.h>
#include <linux/un.h>
#include <net/sock.h>

#define MIN(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })

#define FILE_NAME_LEN 256

struct mknod_data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char pathname[FILE_NAME_LEN];
    int mode;
};

BPF_PERF_OUTPUT(mknod_events);

int syscall__mknod(struct pt_regs *ctx, int dirfd, const char *pathname, mode_t mode, dev_t dev)
{
    struct mknod_data_t mknod_data = {};

    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    mknod_data.pid  = bpf_get_current_pid_tgid() >> 32;
    mknod_data.ppid = task->real_parent->tgid;
    mknod_data.uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&mknod_data.comm, sizeof(mknod_data.comm));
    bpf_probe_read_user(mknod_data.pathname, sizeof(mknod_data.pathname), pathname);
    mknod_data.mode = mode;

    mknod_events.perf_submit(ctx, &mknod_data, sizeof(mknod_data));

    return 0;
}