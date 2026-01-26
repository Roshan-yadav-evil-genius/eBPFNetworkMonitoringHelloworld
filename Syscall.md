[1 tool called]

This is a **tracepoint** that fires on **every single system call** made by any process.

---

## What is `tracepoint/raw_syscalls/sys_enter`?

| Component | Meaning |
|-----------|---------|
| `tracepoint` | A stable kernel hook point (unlike kprobes which can change) |
| `raw_syscalls` | The subsystem for all system calls |
| `sys_enter` | Fires at syscall **entry** (before it executes) |

---

## Tracepoint vs Kprobe

| Aspect | Kprobe | Tracepoint |
|--------|--------|------------|
| **Stability** | Can break between kernel versions | Stable API, won't change |
| **Hook point** | Any kernel function | Predefined instrumentation points |
| **Performance** | Slightly slower | Optimized, faster |
| **Example** | `kprobe/vfs_read` | `tracepoint/raw_syscalls/sys_enter` |

Tracepoints are **preferred** when available because they're stable across kernel updates.

---

## Why `raw_syscalls` Instead of Specific Syscalls?

```
┌─────────────────────────────────────────────────────────────────┐
│                     System Call Options                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Option 1: Hook individual syscalls                              │
│  ─────────────────────────────────                              │
│  @section("tracepoint/syscalls/sys_enter_read")   → only read   │
│  @section("tracepoint/syscalls/sys_enter_write")  → only write  │
│  @section("tracepoint/syscalls/sys_enter_open")   → only open   │
│  ... need 400+ hooks for all syscalls!                          │
│                                                                  │
│  Option 2: Hook ALL syscalls at once (what you use)             │
│  ──────────────────────────────────────────────────             │
│  @section("tracepoint/raw_syscalls/sys_enter")    → EVERYTHING! │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

Your code uses the **raw** version to count **total syscalls**—not caring which specific syscall it is.

---

## What Syscalls Does It Catch?

**ALL of them:**

| Category | Examples |
|----------|----------|
| File I/O | `read`, `write`, `open`, `close`, `stat` |
| Process | `fork`, `exec`, `exit`, `wait` |
| Memory | `mmap`, `brk`, `mprotect` |
| Network | `socket`, `connect`, `send`, `recv` |
| Time | `clock_gettime`, `nanosleep` |
| Signals | `kill`, `sigaction` |
| ... | ~400+ syscalls total |

---

## Visual: When It Fires

```
┌────────────────────────────────────────────────────────────────────┐
│  Application: printf("Hello")                                      │
└────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌────────────────────────────────────────────────────────────────────┐
│  libc: write(1, "Hello", 5)                                        │
└────────────────────────────────────────────────────────────────────┘
                               │
                               ▼ syscall instruction
┌────────────────────────────────────────────────────────────────────┐
│                        Kernel Entry                                 │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  🎯 tracepoint/raw_syscalls/sys_enter FIRES HERE              │ │
│  │                                                                │ │
│  │  Your BPF program:                                            │ │
│  │  1. get_current_cgroup_id() → 12345                          │ │
│  │  2. syscall_count[12345]++                                   │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                               │                                     │
│                               ▼                                     │
│                    sys_write() executes                             │
│                               │                                     │
│                               ▼                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  tracepoint/raw_syscalls/sys_exit (not used in your code)     │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
└────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
                    Return to application
```

---

## Your Code Explained

```186:198:eBPFNetworkMonitoringHelloworld/cgroup_monitor.py
@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def count_syscalls(ctx: c_void_p) -> c_int32:
    cgroup_id = get_current_cgroup_id()       # Which container?
    count_ptr = syscall_count.lookup(cgroup_id)

    if count_ptr:
        new_count = count_ptr + c_uint64(1)   # Increment existing count
        syscall_count.update(cgroup_id, new_count)
    else:
        syscall_count.update(cgroup_id, c_uint64(1))  # First syscall

    return c_int32(0)
```

**Purpose:** Count the **total number of syscalls** per cgroup—a proxy for how "active" a container is.

---

## Why Count Syscalls?

| High Syscall Count Indicates | Example |
|------------------------------|---------|
| CPU-intensive work | Heavy computation with many small I/Os |
| I/O-heavy workload | Lots of file/network operations |
| Potential abuse | Fork bombs, denial of service |
| Container activity | Compare idle vs busy containers |

---

## `sys_enter` vs `sys_exit`

| Tracepoint | When | What you can see |
|------------|------|------------------|
| `sys_enter` | Before syscall runs | Syscall number, arguments |
| `sys_exit` | After syscall completes | Return value, duration |

Your code only uses `sys_enter` because you just want to **count** syscalls, not analyze their results.

---

## Summary

| Aspect | Value |
|--------|-------|
| **Hook point** | `tracepoint/raw_syscalls/sys_enter` |
| **Fires on** | Every syscall entry (400+ types) |
| **What you track** | Total syscall count per cgroup |
| **Why tracepoint** | Stable API, faster than kprobe |
| **Use case** | Measure overall container activity |

This gives you a single metric that represents **"how much work"** each container is asking the kernel to do.