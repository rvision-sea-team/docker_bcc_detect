from bcc import BPF
from util import * # находится в корне репозитория

# имя файла с кодом kernel-части
BPF_FILENAME = "docker_detect.c"

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
close_fnname        = bpf.get_syscall_fnname("close")

connect_fnname      = bpf.get_syscall_fnname("connect")
write_fnname        = bpf.get_syscall_fnname("write")
sendto_fnname       = bpf.get_syscall_fnname("sendto")


# "прикрепляемся" к вызовам указывая имена функций в ядре ответственных за их обработку
# https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#events
bpf.attach_kprobe(event=openat_fname,        fn_name="syscall__openat")
bpf.attach_kretprobe(event=openat_fname,     fn_name="syscall__openat_ret")
bpf.attach_kprobe(event=close_fnname,        fn_name="syscall__close")

bpf.attach_kprobe(event=connect_fnname,      fn_name="syscall__connect")
bpf.attach_kprobe(event=write_fnname,        fn_name="syscall__write")
bpf.attach_kprobe(event=sendto_fnname,       fn_name="syscall__sendto")

# обработчики поступаемых из ядра событий
def handle_connect_unix_event(cpu, data, size):
    event = bpf["connect_unix_events"].event(data)

    proc = Process(event)

    sock_name = event.sock_filename.decode("ascii")

    if not (sock_name.endswith("/docker.sock") and proc.in_container()):
        return 0
    
    message = f"connecting to {sock_name}"

    print_event_message(proc, message)

def handle_write_event(cpu, data, size):

    event = bpf["write_events"].event(data)

    proc = Process(event)

    target = event.filename.decode("ascii", errors='ignore')

    if not (target.endswith("/docker.sock") and proc.in_container()):
        return
    
    write_buf = event.buf[:event.len].decode("ascii", errors='ignore')

    if not '/containers/create' in write_buf:
        return

    if '"Privileged":true' in write_buf:
        message = f"creating privileged container from container\n[data]\n{write_buf}"
    elif '"Binds":[' in write_buf:
        message = f"creating container with \"binds\" from container\n[data]\n{write_buf}"
    else:
        return
    
    print_event_message(proc, message)

# прикрепляем обработчики к событиям
bpf["connect_unix_events"].open_perf_buffer(handle_connect_unix_event)
bpf["write_events"].open_perf_buffer(handle_write_event)

print("%-12s %-7s %-14s %-7s %-40s      %-16s %s" % 
("CONTAINER_ID", "PID", "PCONTAINER_ID", "PPID", "PCOMM", "COMM", "MESSAGE"))

# в бесконечном цикле получаем и обрабатываем поступающие события
while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
