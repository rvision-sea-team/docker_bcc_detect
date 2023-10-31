from bcc import BPF
from util import *

# define BPF program

BPF_FILENAME = "proc_sys_write_detect.c"

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
dup2_fname          = bpf.get_syscall_fnname("dup2")
close_fnname        = bpf.get_syscall_fnname("close")

write_fnname        = bpf.get_syscall_fnname("write")

# "прикрепляемся" к вызовам
# https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#events
bpf.attach_kprobe(event=openat_fname,        fn_name="syscall__openat")
bpf.attach_kretprobe(event=openat_fname,     fn_name="syscall__openat_ret")
bpf.attach_kprobe(event=dup2_fname,          fn_name="syscall__dup2")
bpf.attach_kretprobe(event=dup2_fname,       fn_name="syscall__dup2_ret")
bpf.attach_kprobe(event=close_fnname,        fn_name="syscall__close")

bpf.attach_kprobe(event=write_fnname,        fn_name="syscall__write")

# функция обработчик для событий
def handle_proc_sys_write_event(cpu, data, size):
    global input_buff

    event = bpf["write_events"].event(data)

    proc = Process(event)

    target    = event.filename.decode("ascii")

    if not (target.endswith("/core_pattern") or target.endswith("/uevent_helper")):
        return 0

    write_buf = bytes(event.buf)[:event.len].decode("ascii", errors='ignore')
    
    message = f"writing to {target}\n[data]\n{write_buf}"

    print_event_message(proc, message)


# прикрепляем обработчики к событиям
bpf["write_events"].open_perf_buffer(handle_proc_sys_write_event)

print("%-12s %-7s %-14s %-7s %-40s      %-16s %s" % 
("CONTAINER_ID", "PID", "PCONTAINER_ID", "PPID", "PCOMM", "COMM", "MESSAGE"))

# в бесконечном цикле получаем и обрабатываем поступающие события
while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
