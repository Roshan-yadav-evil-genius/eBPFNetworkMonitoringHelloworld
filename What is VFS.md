## What is VFS?

**VFS (Virtual File System)** is the **abstraction layer** in the Linux kernel that sits between userspace applications and actual filesystems.

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Space                                │
│                                                                  │
│   Application calls: read(fd, buf, count)                       │
│                      write(fd, buf, count)                      │
└──────────────────────────────┬──────────────────────────────────┘
                               │ System Call
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Kernel Space                              │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    VFS Layer                               │  │
│  │                                                            │  │
│  │   vfs_read()  ◄─── YOUR BPF HOOKS HERE ───►  vfs_write()  │  │
│  │                                                            │  │
│  └──────────┬─────────────────┬─────────────────┬────────────┘  │
│             │                 │                 │                │
│             ▼                 ▼                 ▼                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │     ext4     │  │     XFS      │  │     NFS      │           │
│  │  filesystem  │  │  filesystem  │  │  filesystem  │           │
│  └──────────────┘  └──────────────┘  └──────────────┘           │
│             │                 │                 │                │
│             ▼                 ▼                 ▼                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │  Local Disk  │  │  Local Disk  │  │   Network    │           │
│  └──────────────┘  └──────────────┘  └──────────────┘           │
└─────────────────────────────────────────────────────────────────┘
```

---

## Why Hook `vfs_read` / `vfs_write`?

### They Capture **ALL** File I/O

| What gets captured | Examples |
|--------------------|----------|
| Regular files | Reading `/etc/passwd`, writing logs |
| Block devices | Reading from `/dev/sda` |
| Network filesystems | NFS, CIFS, SSHFS |
| Proc/Sys filesystems | `/proc/cpuinfo`, `/sys/class/net` |
| Sockets (sometimes) | Some socket operations go through VFS |
| Pipes | `cat file | grep foo` |

By hooking at the VFS layer, you get **filesystem-agnostic** monitoring—it works the same whether the file is on ext4, XFS, NFS, or tmpfs.

---

## Function Signatures (in Kernel)

```c
// Kernel source: fs/read_write.c

ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
//                    ↑              ↑                ↑               ↑
//                  arg1           arg2             arg3            arg4
//                  (rdi)          (rsi)            (rdx)           (rcx)

ssize_t vfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
//                    ↑                    ↑                    ↑               ↑
//                  arg1                 arg2                 arg3            arg4
```

---

## How Your Code Extracts the Byte Count

```85:100:eBPFNetworkMonitoringHelloworld/cgroup_monitor.py
@bpf
@section("kprobe/vfs_read")
def trace_read(ctx: struct_pt_regs) -> c_int32:
    cg = get_current_cgroup_id()
    count = c_uint64(ctx.dx)          # ◄── ctx.dx = 3rd argument = byte count
    ptr = read_map.lookup(cg)
    if ptr:
        s = read_stats()
        s.bytes = ptr.bytes + count   # ◄── Accumulate bytes
        s.ops = ptr.ops + 1           # ◄── Increment operation count
        read_map.update(cg, s)
    else:
        s = read_stats()
        s.bytes = count
        s.ops = c_uint64(1)
        read_map.update(cg, s)
```

### Register Mapping (x86_64 calling convention)

| Register | Argument | In `vfs_read`/`vfs_write` |
|----------|----------|---------------------------|
| `ctx.di` (RDI) | 1st | `struct file *file` |
| `ctx.si` (RSI) | 2nd | `char *buf` (buffer pointer) |
| `ctx.dx` (RDX) | 3rd | `size_t count` ← **This is what you want!** |
| `ctx.cx` (RCX) | 4th | `loff_t *pos` (file position) |

So `ctx.dx` gives you the **number of bytes** the process is trying to read/write.

---

## kprobe vs kretprobe

Your code uses **kprobe** (entry point):

| Type | When it fires | What you can see |
|------|---------------|------------------|
| **kprobe** | Function **entry** | Arguments (requested bytes) |
| **kretprobe** | Function **exit** | Return value (actual bytes read/written) |

**Trade-off:**
- `kprobe` captures the **requested** count (what the app asked for)
- `kretprobe` captures the **actual** count (what was delivered)

For monitoring purposes, requested count is usually fine. If you need precise accounting, you'd use `kretprobe` and read the return value.

---

## Why Not Hook `read()` / `write()` Syscalls Directly?

| Hook Point | Pros | Cons |
|------------|------|------|
| `sys_read` / `sys_write` | Direct syscall | Misses internal kernel I/O |
| **`vfs_read` / `vfs_write`** | **Catches everything** | Slightly deeper in stack |
| `ext4_file_read` | Filesystem-specific | Only catches ext4 |

VFS is the **sweet spot**—it's low enough to capture all I/O but high enough to be filesystem-agnostic.

---

## Visual: What Happens When You `cat /etc/passwd`

```
┌──────────────────────────────────────────────────────────────────┐
│  $ cat /etc/passwd                                               │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│  User Space: cat calls read(fd, buf, 4096)                       │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼ syscall
┌──────────────────────────────────────────────────────────────────┐
│  Kernel: sys_read() called                                       │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│  VFS: vfs_read(file, buf, 4096, pos)                            │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  🎯 YOUR BPF PROGRAM FIRES HERE!                           │ │
│  │                                                            │ │
│  │  1. get_current_cgroup_id() → 12345                       │ │
│  │  2. ctx.dx → 4096 bytes requested                         │ │
│  │  3. read_map.update(12345, {bytes: 4096, ops: 1})        │ │
│  └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│  ext4: ext4_file_read_iter() → reads from disk                   │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│  Data returned to cat → prints to terminal                       │
└──────────────────────────────────────────────────────────────────┘
```

---

## Summary

| Concept | Explanation |
|---------|-------------|
| **VFS** | Virtual File System—kernel's abstraction layer for all file operations |
| **vfs_read** | Called for every file read, regardless of filesystem |
| **vfs_write** | Called for every file write, regardless of filesystem |
| **ctx.dx** | Contains the byte count (3rd argument per x86_64 ABI) |
| **kprobe** | Hooks at function entry to capture arguments |

This is why VFS hooks are the gold standard for file I/O monitoring—one hook point captures everything!