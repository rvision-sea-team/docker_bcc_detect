#include <uapi/linux/ptrace.h>
#include <linux/un.h>
#include <linux/sched.h>

#define MIN(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })

#define FILE_NAME_LEN 256
#define WRITE_BUF_MAX_LEN 1024

// __ptrace_request 
#define PTRACE_ATTACH 16

struct ptrace_data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 target_pid;
};

struct pwrite_data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    int fd;
    char filename[FILE_NAME_LEN];
    unsigned char buf[WRITE_BUF_MAX_LEN];
    u64 len;
    u64 offset;
};

struct opened_file_data_t {
    int fd;
    char pathname[FILE_NAME_LEN];
};

BPF_PERF_OUTPUT(ptrace_events);
BPF_PERF_OUTPUT(pwrite_events);

BPF_ARRAY(pwrite_data, struct pwrite_data_t, 1);

// промежуточная таблица для сохранения имени файла между входом и выходом из openat
BPF_HASH(temp_opened_files, u64, const char *);

// итоговая таблица сопастовления fd и имени файла
BPF_HASH(opened_files, u64, struct opened_file_data_t);

//
int syscall__openat(struct pt_regs *ctx, int dirfd, const char *pathname, int flags, mode_t mode)
{
    u64 temp_file_id = bpf_get_current_pid_tgid();

    // используем id процесса и группы потока в качестве "идентификатора" файла находящегося в процессе открытия
    // и сохраняем имя файла для последующего мапинга с полученным при выходе дескриптором
    // далее связка "имя файла" -> номер дескриптора будет использована в других вызовах ( напр. pwrite, write )
    // для получения имени файла, к которому осуществляется обращение

    temp_opened_files.update(&temp_file_id, &pathname);
    
    return 0;
}

int syscall__openat_ret(struct pt_regs *ctx)
{
    // используем id процесса и группы потока в качестве "идентификатора" файла находящегося в процессе открытия
    u64 temp_file_id = bpf_get_current_pid_tgid();

    // получаем возвращаемое значение
    // -1 при ошибке
    // иначе - вернется номер открытого дескриптора
    int retval = PT_REGS_RC(ctx);
    
    // ищем ранее сохраненное имя файла с полученным выше "идентификатором" temp_file_id
    const char **pathname = temp_opened_files.lookup(&temp_file_id);
    if (!pathname)
        return 0;

    // при ошибке более не отслеживаем этот файл и удаляем из хэш-таблицы
    if ( retval == -1 ) {
        temp_opened_files.delete(&temp_file_id);
        return 0;
    }

    // получаем "итоговый" id файла из pid и номера полученного дескриптора
    u64 file_id = (bpf_get_current_pid_tgid() & 0xFFFFFFFF00000000) + retval;

    struct opened_file_data_t opened_file = {};

    opened_file.fd = retval;
    bpf_probe_read_user(opened_file.pathname, sizeof(opened_file.pathname), *pathname);

    // сохраняем результат в хэш-таблицу хранящую имена файлов и дескрипторов открытых файлов
    opened_files.update(&file_id, &opened_file);

    // удаляем запись из хэш-таблицы хранящую файлы в процессе открытия
    temp_opened_files.delete(&temp_file_id);

    return 0;
}

// https://man7.org/linux/man-pages/man2/close.2.html
int syscall__close(struct pt_regs *ctx, int fd)
{
    u64 file_id = ( bpf_get_current_pid_tgid() & 0xFFFFFFFF00000000 ) + fd;

    struct opened_file_data_t *opened_file = opened_files.lookup(&file_id);
    if (opened_file)
        opened_files.delete(&file_id);

    return 0;
}

// https://man7.org/linux/man-pages/man2/mount.2.html
int syscall__ptrace(struct pt_regs *ctx,
    u32 request, u32 pid,
    void *addr, void *data)
{
    // отслеживаем только события PTRACE_ATTACH
    if ( request != PTRACE_ATTACH )
        return 0;

    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct ptrace_data_t ptrace_data = {};

    ptrace_data.pid  = pid_tgid >> 32;
    ptrace_data.ppid = task->real_parent->tgid;
    ptrace_data.uid  = bpf_get_current_uid_gid() & 0xffffffff;

    ptrace_data.target_pid = pid;

    ptrace_events.perf_submit(ctx, &ptrace_data, sizeof(ptrace_data));

    return 0;
}

int syscall__pwrite64(struct pt_regs *ctx, int fd, void *buf, u64 buf_len, u64 offset)
{   
    int index = 0;

    struct pwrite_data_t *data = pwrite_data.lookup(&index);
    if (data == NULL) return 1;

    memset(data->filename, 0, FILE_NAME_LEN);

    u64 pid_tgid  = bpf_get_current_pid_tgid();

    // формируем id для хэш-таблице хранящей "маппинг" дескрипторов и имен файлов
    u64 file_id = ( pid_tgid & 0xFFFFFFFF00000000 ) + fd;

    struct opened_file_data_t *opened_file = opened_files.lookup(&file_id);
    if (!opened_file)
        return 0;

    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    data->pid  = pid_tgid >> 32;
    data->ppid = task->real_parent->tgid;
    data->fd   = fd;
    data->uid  = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_probe_read_kernel(data->filename, sizeof(data->filename), opened_file->pathname);
    u32 result_len = MIN(WRITE_BUF_MAX_LEN, buf_len);
    bpf_probe_read_user(data->buf, result_len, buf);
    data->len    = result_len;
    data->offset = offset;

    pwrite_events.perf_submit(ctx, data, sizeof(struct pwrite_data_t));

    return 0;
}