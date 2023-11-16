from bcc import BPF
from util import * # находится в корне репозитория

import stat

# имя файла с кодом kernel-части
BPF_FILENAME = "mknod_detect.c"

try:
    with open(BPF_FILENAME, "r") as bpf_file:
        bpf_text = bpf_file.read()
except:
    print(f"ERROR: cant open {BPF_FILENAME}")
    exit(1)


# инициализируем BPF
bpf = BPF(text=bpf_text, cflags=["-Wno-macro-redefined"])

# получаем имена для системных вызовов
# https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#5-get_syscall_fnname
mknod_fnname        = bpf.get_syscall_fnname("mknodat")


# "прикрепляемся" к вызовам указывая имена функций в ядре ответственных за их обработку
# https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#events
bpf.attach_kprobe(event=mknod_fnname,        fn_name="syscall__mknod")

# обработчик поступаемых из ядра событий
def handle_mknod_event(cpu, data, size):
    event = bpf["mknod_events"].event(data)

    proc = Process(event)

    pathname = event.pathname.decode("ascii")
    mode     = event.mode

    if not (stat.S_ISBLK(mode) and proc.from_container()):
        return
    
    message = f"creating block device {pathname} from container"

    print_event_message(proc, message)

# прикрепляем обработчик к событиям
bpf["mknod_events"].open_perf_buffer(handle_mknod_event)

print("%-12s %-7s %-14s %-7s %-40s      %-16s %s" % 
("CONTAINER_ID", "PID", "PCONTAINER_ID", "PPID", "PCOMM", "COMM", "MESSAGE"))

# в бесконечном цикле получаем и обрабатываем поступающие события
while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
