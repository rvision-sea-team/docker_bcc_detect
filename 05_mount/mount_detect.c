#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/socket.h>
#include <linux/un.h>
#include <net/sock.h>

#define MIN(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })

#define FILE_NAME_LEN 256
#define MOUNT_DATA_MAX_LEN 1024

struct mount_data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[FILE_NAME_LEN];
    char source[FILE_NAME_LEN];
    char target[FILE_NAME_LEN];
    char data[MOUNT_DATA_MAX_LEN];
};

BPF_ARRAY(mount_data, struct mount_data_t, 1);

BPF_PERF_OUTPUT(mount_events);

// https://man7.org/linux/man-pages/man2/mount.2.html
int syscall__mount(struct pt_regs *ctx,
    const char *source, const char *target,
    const char *filesystemtype, unsigned long mountflags,
    const void *m_data)
{
    int index = 0;

    struct mount_data_t *data = mount_data.lookup(&index);
    if (data == NULL) return 1;
    
    memset(data->source, 0, FILE_NAME_LEN);
    memset(data->target, 0, FILE_NAME_LEN);

    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    data->pid  = bpf_get_current_pid_tgid() >> 32;
    data->ppid = task->real_parent->tgid;
    data->uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(data->comm, sizeof(data->comm));
    bpf_probe_read_user(data->source, sizeof(data->source), source);
    bpf_probe_read_user(data->target, sizeof(data->target), target);
    bpf_probe_read_user_str(data->data, sizeof(data->data), m_data);

    mount_events.perf_submit(ctx, data, sizeof(*data));

    return 0;
}