from bcc import BPF
from util import * # находится в корне репозитория

# имя файла с кодом kernel-части
BPF_FILENAME = "gdb_attach_detect.c"

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

ptrace_fname        = bpf.get_syscall_fnname("ptrace")
pwrite_fname        = bpf.get_syscall_fnname("pwrite64")

# "прикрепляемся" к вызовам указывая имена функций в ядре ответственных за их обработку
# https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#events
bpf.attach_kprobe(event=openat_fname,        fn_name="syscall__openat")
bpf.attach_kretprobe(event=openat_fname,     fn_name="syscall__openat_ret")
bpf.attach_kprobe(event=close_fnname,        fn_name="syscall__close")

bpf.attach_kprobe(event=ptrace_fname,        fn_name="syscall__ptrace")
bpf.attach_kprobe(event=pwrite_fname,        fn_name="syscall__pwrite64")

# dict для хранения pid'ов приаттаченных процессов и заодно мапинга из pid в путь до файла
ptraced_pids = {}

# обработчики поступаемых из ядра событий
def handle_ptrace_event(cpu, data, size):
    global ptraced_pids

    event = bpf["ptrace_events"].event(data)

    proc  = Process(event)

    target_pid = event.target_pid
    target_exe = get_pid_realpath(target_pid)

    message = f"ptrace attach to pid: {target_pid} ( {target_exe} )"

    ptraced_pids[target_pid] = target_exe

    print_event_message(proc, message)
    
def handle_pwrite_event(cpu, data, size):
    event = bpf["pwrite_events"].event(data)

    proc    = Process(event)

    target     = event.filename.decode("ascii", errors='ignore')

    if not target.endswith("/mem"):
        return
    
    target_pid  = int(target.split("/")[-2])
    ptraced_pid = ptraced_pids.get(target_pid)

    if not ptraced_pid:
        return 
    
    pwrite_buf = bytes(event.buf)[:event.len].hex()
    
    message = f"pwrite to {target} [ {pwrite_buf} ]"

    print_event_message(proc, message)

# прикрепляем обработчики к событиям
bpf["ptrace_events"].open_perf_buffer(handle_ptrace_event)
bpf["pwrite_events"].open_perf_buffer(handle_pwrite_event)


print("%-12s %-7s %-14s %-7s %-40s      %-16s %s" % 
("CONTAINER_ID", "PID", "PCONTAINER_ID", "PPID", "PCOMM", "COMM", "MESSAGE"))

# в бесконечном цикле получаем и обрабатываем поступающие события
while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
