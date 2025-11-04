# Real-time Memory Profiler using eBPF (Linux)

## Overview
This tool profiles **memory usage and access patterns** of a running Linux process in real time.  
It monitors when a process allocates and deallocates memory, records page-fault activity, and logs both **virtual** and **physical** (PFN) mappings of accessed pages.

The profiler uses **eBPF (via BCC)** tracepoints to intercept:
- `syscalls:sys_enter_mmap` → virtual allocations  
- `syscalls:sys_enter_munmap` → deallocations  
- `exceptions:page_fault_user` → page faults / first physical access  

This project fulfills the goals of the *“Profiling Memory Access Patterns of Linux Processes”* task, developed for research in **memory efficiency for robotics and IoT systems**.

---

##  Features

| Function | Description |
|-----------|--------------|
| **Track virtual allocations** | Logs each `mmap()` and `munmap()` with virtual address and size |
| **Track physical allocations** | Detects user-space page faults to identify when pages are actually backed by physical memory |
| **Virtual → Physical mapping** | Resolves virtual addresses to Physical Frame Numbers (PFNs) using `/proc/[pid]/pagemap` |
| **Real-time tracing** | Prints live updates to console and writes all events to CSV |
| **Lightweight & non-intrusive** | Runs entirely in kernel space via eBPF without modifying the target process |

---

##  How to implement
 Building and Running
1. Build the test workload
gcc alloc_test.c -o alloc_test

2. Run the target process
./alloc_test &
echo $!   # save its PID

3. Start the tracer
sudo ./memtrace_tp.py --pid <PID>


Example output:

[12:14:03] pid=12058 mmap   addr=0x0 len=409600 pfn=N/A
[12:14:03] pid=12058 fault  addr=0x7f1e7c800000 len=4096 pfn=0x19c57
[12:14:04] pid=12058 munmap addr=0x7f1e7c800000 len=409600 pfn=N/A


Press Ctrl + C to stop tracing.
A CSV file memtrace_log.csv will be created.

