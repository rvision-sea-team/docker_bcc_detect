#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/socket.h>
#include <linux/un.h>
#include <net/sock.h>

#define MIN(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })

#define FILE_NAME_LEN 256

#define WRITE_BUF_MAX_LEN 2048

struct connect_unix_data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    int sockfd;
    char sock_filename[FILE_NAME_LEN];
    int retval;
};

struct write_data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    int fd;
    char filename[FILE_NAME_LEN];
    char buf[WRITE_BUF_MAX_LEN];
    int len;
};

struct opened_file_data_t {
    int fd;
    char pathname[FILE_NAME_LEN];
};

struct connected_unix_socket_data_t {
    int fd;
    char pathname[FILE_NAME_LEN];
};

// таблицы для передачи событий из ядра в пользовательское пространство
// https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#2-bpf_perf_output
BPF_PERF_OUTPUT(connect_unix_events);
BPF_PERF_OUTPUT(write_events);

// массивы для обхода ограничения bpf в 512 байт на стэк
// одно из обсуждений с этой "проблемой"
// https://github.com/iovisor/bcc/issues/2306
BPF_ARRAY(write_data, struct write_data_t, 1);
BPF_ARRAY(connect_data, struct connect_unix_data_t, 1);

// промежуточная таблица для сохранения имени файла между входом и выходом из openat
BPF_HASH(temp_opened_files, u64, const char *);

// итоговая таблица сопастовления fd и имени файла
BPF_HASH(opened_files, u64, struct opened_file_data_t);

// https://man7.org/linux/man-pages/man2/connect.2.html
int syscall__connect(struct pt_regs *ctx, int sockfd, struct sockaddr *saddr, u64 addrlen)
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    u64 pid_tgid  = bpf_get_current_pid_tgid();
    u32 pid       = pid_tgid >> 32;
    u32 ppid      = task->real_parent->tgid;
    u32 uid       = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    if ( saddr->sa_family == 1 ) // sa_family == UNIX
    {
        struct sockaddr_un *saddr_un = (struct sockaddr_un*) saddr;

        if ( saddr_un->sun_path[0] == 0) // sun_path пустой
            return 0;
        
        int index = 0;

        struct connect_unix_data_t *data = connect_data.lookup(&index);
        if (data == NULL) return 1;
        
        data->pid     = pid;
        data->ppid    = ppid;
        data->uid     = uid;
        data->sockfd  = sockfd;

        bpf_probe_read_user(data->sock_filename, sizeof(data->sock_filename), saddr_un->sun_path);

        u64 socket_id = ( pid_tgid & 0xFFFFFFFF00000000 ) + sockfd;

        struct opened_file_data_t opened_socket = {};

        opened_socket.fd = sockfd;
        bpf_probe_read_user(opened_socket.pathname, sizeof(opened_socket.pathname), saddr_un->sun_path);

        // сохраняем в хэш-таблицу хранящую имена файлов и дескрипторов открытых файлов
        opened_files.update(&socket_id, &opened_socket);

        connect_unix_events.perf_submit(ctx, data, sizeof(*data));
    }

    return 0;
}

// отслеживаем вызовы openat для "резолва" имен файлов в последующих вызовах ( в частности во write )
// https://man7.org/linux/man-pages/man2/openat.2.html
int syscall__openat(struct pt_regs *ctx, int dirfd, const char *pathname, int flags, mode_t mode)
{
    u64 file_id = bpf_get_current_pid_tgid();

    // используем id процесса и потока в качестве "идентификатора" файла находящегося в процессе открытия
    // и сохраняем имя файла для последующего мапинга с полученным при выходе дескриптором
    // далее связка "имя файла" -> номер дескриптора будет использована в других вызовах ( напр. write)
    // для получения имени файла, к которому осуществляется обращение

    temp_opened_files.update(&file_id, &pathname);
    
    return 0;
}

int syscall__openat_ret(struct pt_regs *ctx)
{
    // используем id процесса и потока в качестве "идентификатора" файла находящегося в процессе открытия
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

    // получаем "итоговый" id файла из id потока и номера полученного дескриптора
    u64 file_id = (bpf_get_current_pid_tgid() & 0xFFFFFFFF00000000) + retval;

    struct opened_file_data_t opened_file = {};

    opened_file.fd = retval;
    bpf_probe_read_user(opened_file.pathname, sizeof(opened_file.pathname), *pathname);

    // сохраняем в хэш-таблицу хранящую имена файлов и дескрипторов открытых файлов
    opened_files.update(&file_id, &opened_file);

    // удаляем из хэш-таблицы хранящую файлы в процессе открытия
    temp_opened_files.delete(&temp_file_id);

    return 0;
}

// https://man7.org/linux/man-pages/man2/write.2.html
int syscall__write(struct pt_regs *ctx, int fd, void *buf, u64 buf_len)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 file_id  = ( pid_tgid & 0xFFFFFFFF00000000 ) + fd;

    struct opened_file_data_t *opened_file = opened_files.lookup(&file_id);
    if (!opened_file) return 0;

    int index = 0;

    struct write_data_t *data = write_data.lookup(&index);
    if (data == NULL) return 1;
    
    memset(data->filename, 0, FILE_NAME_LEN);

    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    data->pid  = pid_tgid >> 32;
    data->ppid = task->real_parent->tgid;
    data->fd   = fd;
    data->uid  = bpf_get_current_uid_gid() & 0xffffffff;
    u32 result_len = MIN(WRITE_BUF_MAX_LEN, buf_len);
    bpf_probe_read_user(data->buf, result_len, buf);
    data->len = result_len;

    bpf_probe_read_kernel(data->filename, sizeof(data->filename), opened_file->pathname);

    write_events.perf_submit(ctx, data, sizeof(*data));

    return 0;
}

// https://man7.org/linux/man-pages/man2/sendto.2.html
int syscall__sendto(struct pt_regs *ctx, int fd, void *buf, u64 buf_len, int flags, struct sockaddr *dest_addr, int addrlen)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 file_id  = ( pid_tgid & 0xFFFFFFFF00000000 ) + fd;

    struct opened_file_data_t *opened_file = opened_files.lookup(&file_id);
    if (!opened_file) return 0;

    int index = 0;

    struct write_data_t *data = write_data.lookup(&index);
    if (data == NULL) return 1;
    
    memset(data->filename, 0, FILE_NAME_LEN);

    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    data->pid  = pid_tgid >> 32;
    data->ppid = task->real_parent->tgid;
    data->fd   = fd;
    data->uid  = bpf_get_current_uid_gid() & 0xffffffff;
    u32 result_len = MIN(WRITE_BUF_MAX_LEN, buf_len);
    bpf_probe_read_user(data->buf, result_len, buf);
    data->len = result_len;

    bpf_probe_read_kernel(data->filename, sizeof(data->filename), opened_file->pathname);

    write_events.perf_submit(ctx, data, sizeof(*data));

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