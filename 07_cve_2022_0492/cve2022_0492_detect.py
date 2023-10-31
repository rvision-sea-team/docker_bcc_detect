from email import message
from bcc import BPF
from util import * 

#
BPF_FILENAME = "cve2022_0492_detect.c"

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
mount_fnname        = bpf.get_syscall_fnname("mount")
unshare_fnname      = bpf.get_syscall_fnname("unshare")


# "прикрепляемся" к вызовам
# https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#events
bpf.attach_kprobe(event=openat_fname,        fn_name="syscall__openat")
bpf.attach_kretprobe(event=openat_fname,     fn_name="syscall__openat_ret")
bpf.attach_kprobe(event=dup2_fname,          fn_name="syscall__dup2")
bpf.attach_kretprobe(event=dup2_fname,       fn_name="syscall__dup2_ret")
bpf.attach_kprobe(event=close_fnname,        fn_name="syscall__close")

bpf.attach_kprobe(event=write_fnname,        fn_name="syscall__write")
bpf.attach_kprobe(event=mount_fnname,        fn_name="syscall__mount")
bpf.attach_kprobe(event=unshare_fnname,      fn_name="syscall__unshare")

# обработчики событий
def handle_write_event(cpu, data, size):
    event = bpf["write_events"].event(data)

    proc = Process(event)

    if not proc.in_container():
        return
    
    target = event.filename.decode("ascii", errors="ignore")

    if not (target.endswith("/release_agent") or target.endswith("/notify_on_release")):
        return
    
    write_buf = event.buf[:event.len].decode("ascii", errors='ignore')

    message = f"writing to {target}\n[data]\n{write_buf}"

    print_event_message(proc, message)

def handle_mount_event(cpu, data, size):
    event = bpf["mount_events"].event(data)
    
    proc = Process(event)

    if not proc.from_container():
        return
    
    source = event.source.decode("ascii")
    if source != "cgroup":
        return
    
    target = event.target.decode("ascii")

    data   = event.data.decode("ascii", errors="ignore")
    if not( "rdma" in data):
        return
    
    message = f"mounting {source} to {target} [options/data]: {data}"

    print_event_message(proc, message)

CLONE_NEWCGROUP = 0x02000000 # new cgroup namespace
CLONE_NEWUSER   = 0x10000000 # new user namespace

def handle_unshare_event(cpu, data, size):
    event = bpf["unshare_events"].event(data)

    proc = Process(event)
    if not proc.from_container():
        return
    
    flags = event.flags

    if not ((flags & CLONE_NEWUSER) and ( flags & CLONE_NEWCGROUP)):
        return
    
    message = f"unshare ({flags}) with user and cgroup namespace from container"

    print_event_message(proc, message)

# прикрепляем обработчики к событиям
bpf["write_events"].open_perf_buffer(handle_write_event)
bpf["mount_events"].open_perf_buffer(handle_mount_event)
bpf["unshare_events"].open_perf_buffer(handle_unshare_event)

print("%-12s %-7s %-14s %-7s %-40s      %-16s %s" % 
("CONTAINER_ID", "PID", "PCONTAINER_ID", "PPID", "PCOMM", "COMM", "MESSAGE"))

# в бесконечном цикле получаем и обрабатываем поступающие события
while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
