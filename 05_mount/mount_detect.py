from asyncio.proactor_events import _ProactorBaseWritePipeTransport
from bcc import BPF
from util import * 

#
BPF_FILENAME = "mount_detect.c"

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
mount_fnname        = bpf.get_syscall_fnname("mount")

# "прикрепляемся" к вызовам
# https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#events
bpf.attach_kprobe(event=mount_fnname,        fn_name="syscall__mount")

# обработчик событий
def handle_mount_event(cpu, data, size):
    event = bpf["mount_events"].event(data)
    
    proc = Process(event)

    if not proc.from_container():
        return
    
    source = event.source.decode("ascii")
    target = event.target.decode("ascii")
    data   = event.data.decode("ascii", errors="ignore")
    if not data:
        data = "none"
    
    message = f"mounting {source} to {target} [options/data]: {data}"

    print_event_message(proc, message)

# прикрепляем обработчик к событиям
bpf["mount_events"].open_perf_buffer(handle_mount_event)

print("%-12s %-7s %-14s %-7s %-40s      %-16s %s" % 
("CONTAINER_ID", "PID", "PCONTAINER_ID", "PPID", "PCOMM", "COMM", "MESSAGE"))

# в бесконечном цикле получаем и обрабатываем поступающие события
while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
