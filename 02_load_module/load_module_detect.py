from bcc import BPF
from util import * # файл находиться в корне репозитория

BPF_FILENAME = "load_module_detect.c"

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
openat_fname        = bpf.get_syscall_fnname("openat")
connect_fnname      = bpf.get_syscall_fnname("connect")
close_fnname        = bpf.get_syscall_fnname("close")

finit_module_fnname = bpf.get_syscall_fnname("finit_module")

# "прикрепляемся" к вызовам указывая имена функций в ядре ответственных за их обработку
# https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#events
bpf.attach_kprobe(event=openat_fname,        fn_name="syscall__openat")
bpf.attach_kretprobe(event=openat_fname,     fn_name="syscall__openat_ret")
bpf.attach_kprobe(event=close_fnname,        fn_name="syscall__close")

bpf.attach_kprobe(event=finit_module_fnname, fn_name="syscall__finit_module")

# обработчик поступаемых из ядра событий
def handle_finit_module(cpu, data, size):
    event = bpf["finit_module_events"].event(data)

    proc = Process(event)

    if not proc.from_container():
        return
    
    pathname = event.pathname.decode("ascii")
    
    message = f" loading {pathname} module from container"

    print_event_message(proc, message)

# прикрепляем обработчик к событиям
bpf["finit_module_events"].open_perf_buffer(handle_finit_module)

print("%-12s %-7s %-14s %-7s %-40s      %-16s %s" % 
("CONTAINER_ID", "PID", "PCONTAINER_ID", "PPID", "PCOMM", "COMM", "MESSAGE"))

# в бесконечном цикле получаем и обрабатываем поступающие события
while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()