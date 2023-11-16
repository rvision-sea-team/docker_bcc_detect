#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/socket.h>
#include <linux/un.h>
#include <net/sock.h>

#define MIN(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })

#define FILE_NAME_LEN 256
#define WRITE_BUF_MAX_LEN 2048

struct write_data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u64 file_id;
    char filename[FILE_NAME_LEN];
    unsigned char buf[WRITE_BUF_MAX_LEN];
    u64 len;
};

struct opened_file_data_t {
    u64 id;
    char pathname[FILE_NAME_LEN];
};

// таблица для передачи событий из ядра в пользовательское пространство
// https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#2-bpf_perf_output
BPF_PERF_OUTPUT(write_events);

// массив для обхода ограничения bpf в 512 байт на стэк
// одно из обсуждений с этой "проблемой"
// https://github.com/iovisor/bcc/issues/2306
BPF_ARRAY(write_data, struct write_data_t, 1);

// промежуточная таблица для сохранения имени файла между входом и выходом из openat
BPF_HASH(temp_opened_files, u64, const char *);

// промежуточная таблица для сохранения имени файла между входом и выходом из dup
BPF_HASH(temp_dup_files, u64, int);

// итоговая таблица сопастовления fd и имени файла
BPF_HASH(opened_files, u64, struct opened_file_data_t);

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

// https://man7.org/linux/man-pages/man2/dup.2.html
int syscall__dup2(struct pt_regs *ctx, int oldfd, int newfd) {
    // используем id процесса и потока в качестве "идентификатора" файла находящегося в процессе дублирования
    // и сохраняем номер переданного ( старого ) дескриптора для последующего мапинга с полученным при выходе дублированным дескриптором
    // далее связка "номер старого дескриптора" -> "номер нового дескриптора" будет использована при выходе из вызова
    // для создания записи в хэш-таблицы открытых файлов с имени файла для старого дескриптора, но с новым номером дескриптора ( дублированным )

    u64 temp_old_id = bpf_get_current_pid_tgid();

    temp_dup_files.update(&temp_old_id, &oldfd);

    return 0;
}

int syscall__dup2_ret(struct pt_regs *ctx) {
    // получаем возвращаемое значение
    // -1 при ошибке
    // иначе - номер дублированного дискриптора
    int retval = PT_REGS_RC(ctx);

    if ( retval == -1 ) {
        return 0;
    }

    // используем id процесса и потока в качестве "идентификатора" файла находящегося в процессе дублирования
    u64 temp_dup_file_id = bpf_get_current_pid_tgid();

    // получаем номер дублируемого дескриптора
    int *old_file_id = temp_dup_files.lookup(&temp_dup_file_id);

    if (old_file_id) {
        u64 pid_tgid = bpf_get_current_pid_tgid();

        // получаем id для записи хранящей имя файла ассоциированного с дублируемым дескриптором в хэш-таблице открытых файлов
        u64 old_opened_file_id = (pid_tgid & 0xFFFFFFFF00000000) + *old_file_id;

        struct opened_file_data_t *target_file = opened_files.lookup(&old_opened_file_id);
        if (!target_file)
            return 0;
        
        // получаем итоговый id для записи в хэш-таблице открытых файлов с новым дескриптором 
        u64 dup_file_id = (pid_tgid & 0xFFFFFFFF00000000) + retval;
        
        struct opened_file_data_t dup_file = {};

        // сохраняем новый дискриптор
        dup_file.fd = retval;

        // и старое имя файла
        bpf_probe_read_kernel(dup_file.pathname, sizeof(dup_file.pathname), target_file->pathname);

        // сохраняем в хэш-таблицу открытых файлов
        opened_files.update(&dup_file_id, &dup_file);

        // удаляем из хэш-таблицы хранящую дескрипторы в процессе дублирования
        temp_dup_files.delete(&temp_dup_file_id);
    }

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
    data->uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    u32 result_len = MIN(WRITE_BUF_MAX_LEN, buf_len);
    bpf_probe_read_user(data->buf, result_len, buf);
    data->len = result_len;
    bpf_probe_read_kernel(data->filename, sizeof(data->filename), opened_file->pathname);

    write_events.perf_submit(ctx, data, sizeof(*data));

    return 0;
}