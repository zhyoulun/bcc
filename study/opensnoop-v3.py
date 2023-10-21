from __future__ import print_function
from bcc import ArgString, BPF
from bcc.containers import filter_by_containers
from bcc.utils import printb
import argparse
from collections import defaultdict
from datetime import datetime, timedelta
import os

# arguments
examples = """examples:
    ./opensnoop                        # trace all open() syscalls
    ./opensnoop -d 10                  # trace for 10 seconds only
    ./opensnoop -n main                # only print process names containing "main"
"""
parser = argparse.ArgumentParser(
    description="Trace open() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-d", "--duration",
    help="total duration of trace in seconds")
parser.add_argument("-n", "--name",
    type=ArgString,
    help="only print process names containing this name")
args = parser.parse_args()
if args.duration:
    args.duration = timedelta(seconds=int(args.duration))

# define BPF program
bpf_text = """
static inline int container_should_be_filtered() {
    return 0;
}

#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>

struct data_t {
    u64 id;
    u64 ts;
    u32 uid;
    int ret;
    char comm[TASK_COMM_LEN];
    char name[NAME_MAX];
    int flags; // EXTENDED_STRUCT_MEMBER
};

BPF_PERF_OUTPUT(events);

#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER) && !defined(__s390x__)
KRETFUNC_PROBE(__x64_sys_open, struct pt_regs *regs, int ret)
{
    const char __user *filename = (char *)PT_REGS_PARM1(regs);
    int flags = PT_REGS_PARM2(regs);
#else
KRETFUNC_PROBE(__x64_sys_open, const char __user *filename, int flags, int ret)
{
#endif

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part
    u32 uid = bpf_get_current_uid_gid();

    // PID_TID_FILTER
    // UID_FILTER
    // FLAGS_FILTER
    if (container_should_be_filtered()) {
        return 0;
    }

    struct data_t data = {};
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    u64 tsp = bpf_ktime_get_ns();

    bpf_probe_read_user_str(&data.name, sizeof(data.name), (void *)filename);
    data.id    = id;
    data.ts    = tsp / 1000;
    data.uid   = bpf_get_current_uid_gid();
    data.flags = flags; // EXTENDED_STRUCT_MEMBER
    data.ret   = ret;

    // SUBMIT_DATA
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER) && !defined(__s390x__)
KRETFUNC_PROBE(__x64_sys_openat, struct pt_regs *regs, int ret)
{
    int dfd = PT_REGS_PARM1(regs);
    const char __user *filename = (char *)PT_REGS_PARM2(regs);
    int flags = PT_REGS_PARM3(regs);
#else
KRETFUNC_PROBE(__x64_sys_openat, int dfd, const char __user *filename, int flags, int ret)
{
#endif

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part
    u32 uid = bpf_get_current_uid_gid();

    // PID_TID_FILTER
    // UID_FILTER
    // FLAGS_FILTER
    if (container_should_be_filtered()) {
        return 0;
    }

    struct data_t data = {};
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    u64 tsp = bpf_ktime_get_ns();

    bpf_probe_read_user_str(&data.name, sizeof(data.name), (void *)filename);
    data.id    = id;
    data.ts    = tsp / 1000;
    data.uid   = bpf_get_current_uid_gid();
    data.flags = flags; // EXTENDED_STRUCT_MEMBER
    data.ret   = ret;

    // SUBMIT_DATA
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

#include <uapi/linux/openat2.h>
#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER) && !defined(__s390x__)
KRETFUNC_PROBE(__x64_sys_openat2, struct pt_regs *regs, int ret)
{
    int dfd = PT_REGS_PARM1(regs);
    const char __user *filename = (char *)PT_REGS_PARM2(regs);
    struct open_how __user how;
    int flags;

    bpf_probe_read_user(&how, sizeof(struct open_how), (struct open_how*)PT_REGS_PARM3(regs));
    flags = how.flags;
#else
KRETFUNC_PROBE(__x64_sys_openat2, int dfd, const char __user *filename, struct open_how __user *how, int ret)
{
    int flags = how->flags;
#endif

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part
    u32 uid = bpf_get_current_uid_gid();

    // PID_TID_FILTER
    // UID_FILTER
    // FLAGS_FILTER
    if (container_should_be_filtered()) {
        return 0;
    }

    struct data_t data = {};
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    u64 tsp = bpf_ktime_get_ns();

    bpf_probe_read_user_str(&data.name, sizeof(data.name), (void *)filename);
    data.id    = id;
    data.ts    = tsp / 1000;
    data.uid   = bpf_get_current_uid_gid();
    data.flags = flags; // EXTENDED_STRUCT_MEMBER
    data.ret   = ret;

    // SUBMIT_DATA
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# initialize BPF
b = BPF(text=bpf_text)
initial_ts = 0

# header
print("%-14s" % ("TIME(s)"), end="")
print("%-6s" % ("UID"), end="")
print("%-6s %-16s %4s %3s " %
      ("PID", "COMM", "FD", "ERR"), end="")
print("PATH")

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    global initial_ts

    skip = False

    # split return value into FD and errno columns
    if event.ret >= 0:
        fd_s = event.ret
        err = 0
    else:
        fd_s = -1
        err = - event.ret

    if not initial_ts:
        initial_ts = event.ts

    if args.name and bytes(args.name) not in event.comm:
        skip = True

    if not skip:
        # if args.timestamp:
        delta = event.ts - initial_ts
        printb(b"%-14.9f" % (float(delta) / 1000000), nl="")
        # if args.print_uid:
        printb(b"%-6d" % event.uid, nl="")
        printb(b"%-6d %-16s %4d %3d " %
                (event.id >> 32, event.comm, fd_s, err), nl="")
        printb(b"%s" % event.name)

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
start_time = datetime.now()
while not args.duration or datetime.now() - start_time < args.duration:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
