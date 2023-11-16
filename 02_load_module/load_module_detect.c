#include <uapi/linux/ptrace.h>
#include <linux/un.h>
#include <linux/sched.h>

#define MIN(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })

#define FILE_NAME_LEN 256

struct finit_module_data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char pathname[FILE_NAME_LEN];
};

struct opened_file_data_t {
    int fd;
    char pathname[FILE_NAME_LEN];
};

// таблица для передачи событий из ядра в пользовательское пространство
// https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#2-bpf_perf_output
BPF_PERF_OUTPUT(finit_module_events);

// промежуточная таблица для сохранения имени файла между входом и выходом из openat
BPF_HASH(temp_opened_files, u64, const char *);

// итоговая таблица сопастовления fd и имени файла
BPF_HASH(opened_files, u64, struct opened_file_data_t);

// отслеживаем вызовы openat для "резолва" имен файлов в последующих вызовах ( в частности во write )
// https://man7.org/linux/man-pages/man2/openat.2.html
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

// https://man7.org/linux/man-pages/man2/finit_module.2.html
int syscall__finit_module(struct pt_regs *ctx, int fd, const char *param_values, int flags){
    struct finit_module_data_t finit_module_data = {};

    u64 pid_tgid  = bpf_get_current_pid_tgid();
    u64 file_id   = ( pid_tgid & 0xFFFFFFFF00000000 ) + fd;

    struct opened_file_data_t *opened_file = opened_files.lookup(&file_id);
    if (!opened_file)
        return 0;
    
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    finit_module_data.pid  = pid_tgid >> 32;
    finit_module_data.ppid = task->real_parent->tgid;
    finit_module_data.uid  = bpf_get_current_uid_gid() & 0xffffffff;

    bpf_probe_read_kernel(finit_module_data.pathname, sizeof(finit_module_data.pathname), opened_file->pathname);

    finit_module_events.perf_submit(ctx, &finit_module_data, sizeof(finit_module_data));

    return 0;
}