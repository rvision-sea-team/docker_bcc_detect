import os

def get_ppid(pid):
    try:
        with open(f"/proc/{pid}/status") as status:
            for line in status:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except IOError:
        return None

def get_container_id(pid):
    container_id = ""

    try:
        with open(f"/proc/{pid}/cpuset", "r") as cpuset_file:
            cpuset = cpuset_file.read()
    except IOError:
        return container_id
    
    if "/docker" in cpuset:
        container_id = cpuset.split("/")[-1].replace("docker-", "")[:12]

    return container_id

def get_pid_realpath(pid):
    try:
        path = os.readlink(f"/proc/{pid}/exe")
    except IOError:
        return ""
    
    return path

def print_event_message(proc, message):
    print("%-12s %-7d %-14s %-7d %-40s  ->  %-16s %s" % 
    (proc.container_id, proc.pid, proc.parent_container_id, proc.ppid, proc.parent_comm, proc.comm, message))

class Process:
    def __init__(self, event):
        # current
        self.pid          = event.pid

        self.comm = None
        try:
            self.comm         = event.comm.decode("ascii", errors="ignore")
        except:
            if not self.comm:
                self.comm = get_pid_realpath(self.pid)
            else:
                self.comm = "-"
        
        self.container_id = get_container_id(self.pid)

        # parent
        self.ppid = event.ppid
        if not self.ppid:
            self.ppid = get_ppid(self.pid)

        if self.ppid:
            self.parent_container_id = get_container_id(self.ppid)
            self.parent_comm         = get_pid_realpath(self.ppid)
        else:
            self.parent_container_id = "-"
            self.parent_comm         = "-"
    
    def in_container(self):
        if self.container_id != "-":
            return True
        else:
            return False
    
    def from_container(self):
        if self.parent_container_id != "-":
            return True
        else:
            return False
