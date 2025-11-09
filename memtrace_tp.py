#!/usr/bin/env python3
from bcc import BPF
import argparse, time, csv, os, struct

# -------------------- Parse Arguments -------------------- #
parser = argparse.ArgumentParser()
parser.add_argument("--pid", type=int, required=True, help="PID to trace")
args = parser.parse_args()
target_pid = args.pid

# -------------------- BPF Program -------------------- #
program = r"""
#include <uapi/linux/ptrace.h>
BPF_PERF_OUTPUT(events);

struct evt_t {
    u64 ts;
    u32 pid;
    u64 addr;
    u64 len;
    char type[8];
};

static int submit(void *ctx, const char *t, u64 addr, u64 len) {
    struct evt_t e = {};
    e.ts  = bpf_ktime_get_ns();
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.addr = addr;
    e.len  = len;
    __builtin_memcpy(e.type, t, 7);
    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != (u32)PID_FILTER) return 0;
    return submit(args, "mmap", args->addr, args->len);
}

TRACEPOINT_PROBE(syscalls, sys_enter_munmap) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != (u32)PID_FILTER) return 0;
    return submit(args, "munmap", args->addr, args->len);
}

TRACEPOINT_PROBE(exceptions, page_fault_user) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != (u32)PID_FILTER) return 0;
    return submit(args, "fault", args->address, 4096);
}
""".replace("PID_FILTER", str(target_pid))

b = BPF(text=program)

# -------------------- Virtual→Physical Mapping -------------------- #
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")

def virt_to_pfn(pid, vaddr):
    """Return (present, swapped, soft_dirty, file_page, exclusive, pfn)."""
    try:
        page_vaddr = vaddr & ~(PAGE_SIZE - 1)
        index = (page_vaddr // PAGE_SIZE) * 8
        with open(f"/proc/{pid}/pagemap", "rb") as f:
            f.seek(index)
            entry = struct.unpack("Q", f.read(8))[0]

        present     = (entry >> 63) & 1
        swapped     = (entry >> 62) & 1
        soft_dirty  = (entry >> 55) & 1
        file_page   = (entry >> 54) & 1
        exclusive   = (entry >> 53) & 1
        pfn         = (entry & ((1 << 55) - 1)) if (present and not swapped) else None

        return present, swapped, soft_dirty, file_page, exclusive, pfn
    except Exception:
        return 0, 0, 0, 0, 0, None

# -------------------- CSV Setup -------------------- #
logf = open("memtrace_log.csv", "w", newline="")
writer = csv.writer(logf)
writer.writerow(["timestamp_ns","pid","event","address","length","pfn","present","swapped","soft_dirty","file","exclusive"])

# -------------------- Event Handler -------------------- #
allocs = frees = faults = 0

def on_event(cpu, data, size):
    global allocs, frees, faults
    e = b["events"].event(data)
    etype = e.type.decode()

    if etype == "mmap":
        allocs += 1
    elif etype == "munmap":
        frees += 1
    elif etype == "fault":
        faults += 1

    if etype == "fault":
        present, swapped, soft_dirty, file_page, exclusive, pfn = virt_to_pfn(target_pid, e.addr)
        pfn_str = hex(pfn) if pfn is not None else "N/A"
        print(f"[{time.strftime('%H:%M:%S')}] pid={e.pid:<6} {etype:<6} "
              f"addr=0x{e.addr:x} len={e.len:<7} "
              f"pfn={pfn_str:<10} present={present} swapped={swapped} "
              f"soft_dirty={soft_dirty} file={file_page} exclusive={exclusive}")
    else:
        pfn_str = "N/A"
        print(f"[{time.strftime('%H:%M:%S')}] pid={e.pid:<6} {etype:<6} "
              f"addr=0x{e.addr:x} len={e.len:<7} pfn={pfn_str}")

    writer.writerow([e.ts, e.pid, etype, hex(e.addr), e.len, pfn_str,
                     present if etype=="fault" else "N/A",
                     swapped if etype=="fault" else "N/A",
                     soft_dirty if etype=="fault" else "N/A",
                     file_page if etype=="fault" else "N/A",
                     exclusive if etype=="fault" else "N/A"])
    logf.flush()

# -------------------- Run Trace -------------------- #
b["events"].open_perf_buffer(on_event, page_cnt=64)
print(f"[attached] tracepoints: sys_enter_mmap, sys_enter_munmap, exceptions:page_fault_user")
print("Tracing… Ctrl-C to stop.")

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    pass
finally:
    logf.close()
    print("\nSaved: memtrace_log.csv")

