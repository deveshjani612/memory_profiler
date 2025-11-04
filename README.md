# memory_profiler
“Profiling Memory Access Patterns of Linux Processes.”
# 🧩 Real-time Memory Profiler using eBPF (Linux)

## Overview
This tool profiles **memory usage and access patterns** of a running Linux process in real time.  
It monitors when a process allocates and deallocates memory, records page-fault activity, and logs both **virtual** and **physical** (PFN) mappings of accessed pages.

The profiler uses **eBPF (via BCC)** tracepoints to intercept:
- `syscalls:sys_enter_mmap` → virtual allocations  
- `syscalls:sys_enter_munmap` → deallocations  
- `exceptions:page_fault_user` → page faults / first physical access  

This project fulfills the goals of the *“Profiling Memory Access Patterns of Linux Processes”* task, developed for research in **memory efficiency for robotics and IoT systems**.

---

## ✨ Features

| Function | Description |
|-----------|--------------|
| **Track virtual allocations** | Logs each `mmap()` and `munmap()` with virtual address and size |
| **Track physical allocations** | Detects user-space page faults to identify when pages are actually backed by physical memory |
| **Virtual → Physical mapping** | Resolves virtual addresses to Physical Frame Numbers (PFNs) using `/proc/[pid]/pagemap` |
| **Real-time tracing** | Prints live updates to console and writes all events to CSV |
| **Lightweight & non-intrusive** | Runs entirely in kernel space via eBPF without modifying the target process |

---

## 📁 Repository Structure

