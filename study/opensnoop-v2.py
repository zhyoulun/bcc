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
    ./opensnoop -T                     # include timestamps
    ./opensnoop -U                     # include UID
    ./opensnoop -d 10                  # trace for 10 seconds only
    ./opensnoop -n main                # only print process names containing "main"
    ./opensnoop --cgroupmap mappath    # only trace cgroups in this BPF map
    ./opensnoop --mntnsmap mappath     # only trace mount namespaces in the map
"""
parser = argparse.ArgumentParser(
    description="Trace open() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-U", "--print-uid", action="store_true",
    help="print UID column")
parser.add_argument("--cgroupmap",
    help="trace cgroups in this BPF map only")
parser.add_argument("--mntnsmap",
    help="trace mount namespaces in this BPF map only")
parser.add_argument("-d", "--duration",
    help="total duration of trace in seconds")
parser.add_argument("-n", "--name",
    type=ArgString,
    help="only print process names containing this name")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
parser.add_argument("-b", "--buffer-pages", type=int, default=64,
    help="size of the perf ring buffer "
        "(must be a power of two number of pages and defaults to 64)")
args = parser.parse_args()
debug = 0
if args.duration:
    args.duration = timedelta(seconds=int(args.duration))

# define BPF program
bpf_text = """
#define FULLPATH
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>
#ifdef FULLPATH
#include <linux/fs_struct.h>
#include <linux/dcache.h>

#define MAX_ENTRIES 32

enum event_type {
    EVENT_ENTRY,
    EVENT_END,
};
#endif

struct val_t {
    u64 id;
    char comm[TASK_COMM_LEN];
    const char *fname;
    int flags; // EXTENDED_STRUCT_MEMBER
};

struct data_t {
    u64 id;
    u64 ts;
    u32 uid;
    int ret;
    char comm[TASK_COMM_LEN];
#ifdef FULLPATH
    enum event_type type;
#endif
    char name[NAME_MAX];
    int flags; // EXTENDED_STRUCT_MEMBER
};

BPF_PERF_OUTPUT(events);
"""

bpf_text_kprobe = """
BPF_HASH(infotmp, u64, struct val_t);

int trace_return(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp;
    struct data_t data = {};

    u64 tsp = bpf_ktime_get_ns();

    valp = infotmp.lookup(&id);
    if (valp == 0) {
        // missed entry
        return 0;
    }

    bpf_probe_read_kernel(&data.comm, sizeof(data.comm), valp->comm);
    bpf_probe_read_user_str(&data.name, sizeof(data.name), (void *)valp->fname);
    data.id = valp->id;
    data.ts = tsp / 1000;
    data.uid = bpf_get_current_uid_gid();
    data.flags = valp->flags; // EXTENDED_STRUCT_MEMBER
    data.ret = PT_REGS_RC(ctx);

    // SUBMIT_DATA
    events.perf_submit(ctx, &data, sizeof(data));

    infotmp.delete(&id);

    return 0;
}
"""

bpf_text_kprobe_header_open = """
int syscall__trace_entry_open(struct pt_regs *ctx, const char __user *filename, int flags)
{
"""

bpf_text_kprobe_header_openat = """
int syscall__trace_entry_openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags)
{
"""

bpf_text_kprobe_header_openat2 = """
#include <uapi/linux/openat2.h>
int syscall__trace_entry_openat2(struct pt_regs *ctx, int dfd, const char __user *filename, struct open_how *how)
{
    int flags = how->flags;
"""

bpf_text_kprobe_body = """
    struct val_t val = {};
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

    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.id = id;
        val.fname = filename;
        val.flags = flags; // EXTENDED_STRUCT_MEMBER
        infotmp.update(&id, &val);
    }

    return 0;
};
"""

bpf_text_kfunc_header_open = """
#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER) && !defined(__s390x__)
KRETFUNC_PROBE(FNNAME, struct pt_regs *regs, int ret)
{
    const char __user *filename = (char *)PT_REGS_PARM1(regs);
    int flags = PT_REGS_PARM2(regs);
#else
KRETFUNC_PROBE(FNNAME, const char __user *filename, int flags, int ret)
{
#endif
"""

bpf_text_kfunc_header_openat = """
#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER) && !defined(__s390x__)
KRETFUNC_PROBE(FNNAME, struct pt_regs *regs, int ret)
{
    int dfd = PT_REGS_PARM1(regs);
    const char __user *filename = (char *)PT_REGS_PARM2(regs);
    int flags = PT_REGS_PARM3(regs);
#else
KRETFUNC_PROBE(FNNAME, int dfd, const char __user *filename, int flags, int ret)
{
#endif
"""

bpf_text_kfunc_header_openat2 = """
#include <uapi/linux/openat2.h>
#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER) && !defined(__s390x__)
KRETFUNC_PROBE(FNNAME, struct pt_regs *regs, int ret)
{
    int dfd = PT_REGS_PARM1(regs);
    const char __user *filename = (char *)PT_REGS_PARM2(regs);
    struct open_how __user how;
    int flags;

    bpf_probe_read_user(&how, sizeof(struct open_how), (struct open_how*)PT_REGS_PARM3(regs));
    flags = how.flags;
#else
KRETFUNC_PROBE(FNNAME, int dfd, const char __user *filename, struct open_how __user *how, int ret)
{
    int flags = how->flags;
#endif
"""

bpf_text_kfunc_body = """
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

b = BPF(text='')
# open and openat are always in place since 2.6.16
fnname_open = b.get_syscall_prefix().decode() + 'open'
fnname_openat = b.get_syscall_prefix().decode() + 'openat'
fnname_openat2 = b.get_syscall_prefix().decode() + 'openat2'
if b.ksymname(fnname_openat2) == -1:
    fnname_openat2 = None

# if args.full_path:
#     bpf_text = "#define FULLPATH\n" + bpf_text

is_support_kfunc = BPF.support_kfunc()
if is_support_kfunc:
    bpf_text += bpf_text_kfunc_header_open.replace('FNNAME', fnname_open)
    bpf_text += bpf_text_kfunc_body

    bpf_text += bpf_text_kfunc_header_openat.replace('FNNAME', fnname_openat)
    bpf_text += bpf_text_kfunc_body

    if fnname_openat2:
        bpf_text += bpf_text_kfunc_header_openat2.replace('FNNAME', fnname_openat2)
        bpf_text += bpf_text_kfunc_body
else:
    bpf_text += bpf_text_kprobe

    bpf_text += bpf_text_kprobe_header_open
    bpf_text += bpf_text_kprobe_body

    bpf_text += bpf_text_kprobe_header_openat
    bpf_text += bpf_text_kprobe_body

    if fnname_openat2:
        bpf_text += bpf_text_kprobe_header_openat2
        bpf_text += bpf_text_kprobe_body

bpf_text = filter_by_containers(args) + bpf_text

if debug or args.ebpf:
    print(bpf_text)
    print("----------")
    print(fnname_open)
    print(fnname_openat)
    print(fnname_openat2)
    print(is_support_kfunc)
    print("----------")
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)
if not is_support_kfunc:
    b.attach_kprobe(event=fnname_open, fn_name="syscall__trace_entry_open")
    b.attach_kretprobe(event=fnname_open, fn_name="trace_return")

    b.attach_kprobe(event=fnname_openat, fn_name="syscall__trace_entry_openat")
    b.attach_kretprobe(event=fnname_openat, fn_name="trace_return")

    if fnname_openat2:
        b.attach_kprobe(event=fnname_openat2, fn_name="syscall__trace_entry_openat2")
        b.attach_kretprobe(event=fnname_openat2, fn_name="trace_return")

initial_ts = 0

# header
if args.timestamp:
    print("%-14s" % ("TIME(s)"), end="")
if args.print_uid:
    print("%-6s" % ("UID"), end="")
print("%-6s %-16s %4s %3s " %
      ("PID", "COMM", "FD", "ERR"), end="")
print("PATH")

class EventType(object):
    EVENT_ENTRY = 0
    EVENT_END = 1

entries = defaultdict(list)

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    global initial_ts

    # if not args.full_path or event.type == EventType.EVENT_END:
    if True:
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

        # if args.failed and (event.ret >= 0):
        #     skip = True

        if args.name and bytes(args.name) not in event.comm:
            skip = True

        if not skip:
            if args.timestamp:
                delta = event.ts - initial_ts
                printb(b"%-14.9f" % (float(delta) / 1000000), nl="")

            if args.print_uid:
                printb(b"%-6d" % event.uid, nl="")

            printb(b"%-6d %-16s %4d %3d " %
                   (event.id >> 32, event.comm, fd_s, err), nl="")

            printb(b"%s" % event.name)

    elif event.type == EventType.EVENT_ENTRY:
        entries[event.id].append(event.name)

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=args.buffer_pages)
start_time = datetime.now()
while not args.duration or datetime.now() - start_time < args.duration:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
