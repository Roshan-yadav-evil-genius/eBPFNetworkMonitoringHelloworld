"""Simple Cgroup Monitor - Monitor a specific cgroup by name with matplotlib graphs."""

import sys
import os
import argparse
import time
from pathlib import Path
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib.ticker import FuncFormatter

# Add project root to Python path to allow importing vmlinux
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from pythonbpf import bpf, map, section, bpfglobal, struct, BPF
from pythonbpf.maps import HashMap
from pythonbpf.helper import get_current_cgroup_id
from ctypes import c_int32, c_uint64, c_void_p
from vmlinux import struct_pt_regs, struct_sk_buff

from data_collection import ContainerDataCollector, ContainerStats


# ==================== BPF Structs ====================


@bpf
@struct
class read_stats:
    bytes: c_uint64
    ops: c_uint64


@bpf
@struct
class write_stats:
    bytes: c_uint64
    ops: c_uint64


@bpf
@struct
class net_stats:
    rx_packets: c_uint64
    tx_packets: c_uint64
    rx_bytes: c_uint64
    tx_bytes: c_uint64


# ==================== BPF Maps ====================


@bpf
@map
def read_map() -> HashMap:
    return HashMap(key=c_uint64, value=read_stats, max_entries=1024)


@bpf
@map
def write_map() -> HashMap:
    return HashMap(key=c_uint64, value=write_stats, max_entries=1024)


@bpf
@map
def net_stats_map() -> HashMap:
    return HashMap(key=c_uint64, value=net_stats, max_entries=1024)


@bpf
@map
def syscall_count() -> HashMap:
    return HashMap(key=c_uint64, value=c_uint64, max_entries=1024)


# ==================== File I/O Tracing ====================


@bpf
@section("kprobe/vfs_read")
def trace_read(ctx: struct_pt_regs) -> c_int32:
    cg = get_current_cgroup_id()
    count = c_uint64(ctx.dx)
    ptr = read_map.lookup(cg)
    if ptr:
        s = read_stats()
        s.bytes = ptr.bytes + count
        s.ops = ptr.ops + 1
        read_map.update(cg, s)
    else:
        s = read_stats()
        s.bytes = count
        s.ops = c_uint64(1)
        read_map.update(cg, s)

    return c_int32(0)


@bpf
@section("kprobe/vfs_write")
def trace_write(ctx1: struct_pt_regs) -> c_int32:
    cg = get_current_cgroup_id()
    count = c_uint64(ctx1.dx)
    ptr = write_map.lookup(cg)

    if ptr:
        s = write_stats()
        s.bytes = ptr.bytes + count
        s.ops = ptr.ops + 1
        write_map.update(cg, s)
    else:
        s = write_stats()
        s.bytes = count
        s.ops = c_uint64(1)
        write_map.update(cg, s)

    return c_int32(0)


# ==================== Network I/O Tracing ====================


@bpf
@section("kprobe/__netif_receive_skb")
def trace_netif_rx(ctx2: struct_pt_regs) -> c_int32:
    cgroup_id = get_current_cgroup_id()
    skb = struct_sk_buff(ctx2.di)
    pkt_len = c_uint64(skb.len)

    stats_ptr = net_stats_map.lookup(cgroup_id)

    if stats_ptr:
        stats = net_stats()
        stats.rx_packets = stats_ptr.rx_packets + 1
        stats.tx_packets = stats_ptr.tx_packets
        stats.rx_bytes = stats_ptr.rx_bytes + pkt_len
        stats.tx_bytes = stats_ptr.tx_bytes
        net_stats_map.update(cgroup_id, stats)
    else:
        stats = net_stats()
        stats.rx_packets = c_uint64(1)
        stats.tx_packets = c_uint64(0)
        stats.rx_bytes = pkt_len
        stats.tx_bytes = c_uint64(0)
        net_stats_map.update(cgroup_id, stats)

    return c_int32(0)


@bpf
@section("kprobe/__dev_queue_xmit")
def trace_dev_xmit(ctx3: struct_pt_regs) -> c_int32:
    cgroup_id = get_current_cgroup_id()
    skb = struct_sk_buff(ctx3.di)
    pkt_len = c_uint64(skb.len)

    stats_ptr = net_stats_map.lookup(cgroup_id)

    if stats_ptr:
        stats = net_stats()
        stats.rx_packets = stats_ptr.rx_packets
        stats.tx_packets = stats_ptr.tx_packets + 1
        stats.rx_bytes = stats_ptr.rx_bytes
        stats.tx_bytes = stats_ptr.tx_bytes + pkt_len
        net_stats_map.update(cgroup_id, stats)
    else:
        stats = net_stats()
        stats.rx_packets = c_uint64(0)
        stats.tx_packets = c_uint64(1)
        stats.rx_bytes = c_uint64(0)
        stats.tx_bytes = pkt_len
        net_stats_map.update(cgroup_id, stats)

    return c_int32(0)


# ==================== Syscall Tracing ====================


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def count_syscalls(ctx: c_void_p) -> c_int32:
    cgroup_id = get_current_cgroup_id()
    count_ptr = syscall_count.lookup(cgroup_id)

    if count_ptr:
        new_count = count_ptr + c_uint64(1)
        syscall_count.update(cgroup_id, new_count)
    else:
        syscall_count.update(cgroup_id, c_uint64(1))

    return c_int32(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


# ==================== Main ====================

if __name__ == "__main__":
    # ==================== Cgroup Management ====================
    
    def get_cgroup_path(cgroup_name: str) -> Path:
        """Get the full path to the cgroup directory."""
        # Try cgroup v2 first (most common on modern systems)
        cgroup_v2_path = Path(f"/sys/fs/cgroup/{cgroup_name}")
        if cgroup_v2_path.exists() or Path("/sys/fs/cgroup").exists():
            return cgroup_v2_path
        
        # Fallback to cgroup v1 (unified hierarchy)
        # Check common mount points
        for mount_point in ["/sys/fs/cgroup/unified", "/sys/fs/cgroup"]:
            test_path = Path(mount_point) / cgroup_name
            if test_path.exists():
                return test_path
        
        # Default to cgroup v2 location
        return cgroup_v2_path

    def create_cgroup(cgroup_name: str) -> Path:
        """Create a cgroup if it doesn't exist. Returns the cgroup path."""
        cgroup_path = get_cgroup_path(cgroup_name)
        
        if cgroup_path.exists():
            print(f"✅ Cgroup '{cgroup_name}' already exists at {cgroup_path}")
            return cgroup_path
        
        try:
            # Create the cgroup directory
            cgroup_path.mkdir(parents=True, exist_ok=True)
            print(f"✅ Created cgroup '{cgroup_name}' at {cgroup_path}")
            return cgroup_path
        except PermissionError:
            print(f"❌ Permission denied: Cannot create cgroup at {cgroup_path}")
            print("   Please run with sudo or ensure you have permissions")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error creating cgroup: {e}")
            sys.exit(1)

    def get_cgroup_id(cgroup_path: Path) -> int:
        """Get the cgroup ID from the cgroup directory inode."""
        try:
            stat_info = os.stat(cgroup_path)
            cgroup_id = stat_info.st_ino
            return cgroup_id
        except Exception as e:
            print(f"❌ Error getting cgroup ID: {e}")
            sys.exit(1)

    # ==================== Matplotlib Helper Functions ====================

    def _format_bytes(bytes_val: float) -> str:
        """Format bytes into human-readable string."""
        if bytes_val < 0:
            bytes_val = 0
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if bytes_val < 1024.0:
                return f"{bytes_val:.1f}{unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.1f}PB"

    def _calculate_rates(history: list) -> dict:
        """Calculate per-second rates from history."""
        if len(history) < 2:
            return {
                "syscalls_per_sec": 0.0,
                "rx_bytes_per_sec": 0.0,
                "tx_bytes_per_sec": 0.0,
                "rx_pkts_per_sec": 0.0,
                "tx_pkts_per_sec": 0.0,
                "read_bytes_per_sec": 0.0,
                "write_bytes_per_sec": 0.0,
                "read_ops_per_sec": 0.0,
                "write_ops_per_sec": 0.0,
            }

        recent = history[-1]
        previous = history[-2]
        time_delta = recent.timestamp - previous.timestamp

        if time_delta <= 0:
            time_delta = 1.0

        return {
            "syscalls_per_sec": (recent.syscall_count - previous.syscall_count) / time_delta,
            "rx_bytes_per_sec": (recent.rx_bytes - previous.rx_bytes) / time_delta,
            "tx_bytes_per_sec": (recent.tx_bytes - previous.tx_bytes) / time_delta,
            "rx_pkts_per_sec": (recent.rx_packets - previous.rx_packets) / time_delta,
            "tx_pkts_per_sec": (recent.tx_packets - previous.tx_packets) / time_delta,
            "read_bytes_per_sec": (recent.read_bytes - previous.read_bytes) / time_delta,
            "write_bytes_per_sec": (recent.write_bytes - previous.write_bytes) / time_delta,
            "read_ops_per_sec": (recent.read_ops - previous.read_ops) / time_delta,
            "write_ops_per_sec": (recent.write_ops - previous.write_ops) / time_delta,
        }

    # ==================== Matplotlib Graph Setup ====================

    def setup_graphs(cgroup_name: str):
        """Initialize matplotlib figure with two subplots."""
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
        fig.suptitle(f'Cgroup Monitor: {cgroup_name}', fontsize=14, fontweight='bold')
        
        # Network I/O subplot (top)
        ax1.set_title('Network I/O', fontweight='bold')
        ax1.set_xlabel('Time (samples)')
        ax1.set_ylabel('Bytes')
        ax1.grid(True, alpha=0.3)
        ax1.legend(loc='upper left')
        
        # File I/O subplot (bottom)
        ax2.set_title('File I/O', fontweight='bold')
        ax2.set_xlabel('Time (samples)')
        ax2.set_ylabel('Bytes')
        ax2.grid(True, alpha=0.3)
        ax2.legend(loc='upper left')
        
        plt.tight_layout()
        return fig, ax1, ax2

    def update_graphs(frame, collector, cgroup_id, ax1, ax2):
        """Update function for matplotlib animation."""
        # Get current stats
        stats = collector.get_stats_for_cgroup(cgroup_id)
        history = collector.get_history(cgroup_id)
        rates = _calculate_rates(history)
        
        if len(history) < 2:
            return
        
        # Prepare data
        samples = list(range(len(history)))
        rx_bytes = [s.rx_bytes for s in history]
        tx_bytes = [s.tx_bytes for s in history]
        read_bytes = [s.read_bytes for s in history]
        write_bytes = [s.write_bytes for s in history]
        
        # Clear and update Network I/O graph
        ax1.clear()
        ax1.plot(samples, rx_bytes, 'g-', label=f'RX ({_format_bytes(rates["rx_bytes_per_sec"])}/s)', linewidth=2)
        ax1.plot(samples, tx_bytes, 'orange', label=f'TX ({_format_bytes(rates["tx_bytes_per_sec"])}/s)', linewidth=2)
        ax1.set_title(f'Network I/O - RX: {_format_bytes(stats.rx_bytes)}, TX: {_format_bytes(stats.tx_bytes)}', fontweight='bold')
        ax1.set_xlabel('Time (samples)')
        ax1.set_ylabel('Bytes')
        ax1.grid(True, alpha=0.3)
        ax1.legend(loc='upper left')
        
        # Format y-axis for Network I/O
        ax1.yaxis.set_major_formatter(FuncFormatter(lambda x, p: _format_bytes(x)))
        
        # Clear and update File I/O graph
        ax2.clear()
        ax2.plot(samples, read_bytes, 'b-', label=f'Read ({_format_bytes(rates["read_bytes_per_sec"])}/s)', linewidth=2)
        ax2.plot(samples, write_bytes, 'r-', label=f'Write ({_format_bytes(rates["write_bytes_per_sec"])}/s)', linewidth=2)
        ax2.set_title(f'File I/O - Read: {_format_bytes(stats.read_bytes)}, Write: {_format_bytes(stats.write_bytes)}', fontweight='bold')
        ax2.set_xlabel('Time (samples)')
        ax2.set_ylabel('Bytes')
        ax2.grid(True, alpha=0.3)
        ax2.legend(loc='upper left')
        
        # Format y-axis for File I/O
        ax2.yaxis.set_major_formatter(FuncFormatter(lambda x, p: _format_bytes(x)))
        
        plt.tight_layout()

    # ==================== Main Execution ====================
    parser = argparse.ArgumentParser(description="Monitor a specific cgroup with eBPF")
    parser.add_argument("cgroup_name", help="Name of the cgroup to monitor")
    args = parser.parse_args()

    cgroup_name = args.cgroup_name

    print("🔥 Setting up cgroup...")
    cgroup_path = create_cgroup(cgroup_name)
    cgroup_id = get_cgroup_id(cgroup_path)
    print(f"✅ Cgroup ID: {cgroup_id}")

    print("🔥 Loading BPF programs...")

    # Load and attach BPF program
    b = BPF()
    b.load()
    b.attach_all()

    # Get map references and enable struct deserialization
    read_map_ref = b["read_map"]
    write_map_ref = b["write_map"]
    net_stats_map_ref = b["net_stats_map"]
    syscall_count_ref = b["syscall_count"]

    read_map_ref.set_value_struct("read_stats")
    write_map_ref.set_value_struct("write_stats")
    net_stats_map_ref.set_value_struct("net_stats")

    print("✅ BPF programs loaded and attached")

    # Setup data collector
    collector = ContainerDataCollector(
        read_map_ref, write_map_ref, net_stats_map_ref, syscall_count_ref
    )

    # Update collector cache with our cgroup
    from data_collection import CgroupInfo
    collector._cgroup_cache[cgroup_id] = CgroupInfo(
        id=cgroup_id, name=cgroup_name, path=str(cgroup_path)
    )

    print("✅ Starting monitor...")
    print(f"📊 Monitoring cgroup: {cgroup_name} (ID: {cgroup_id})")
    print("   Close the graph window to quit\n")

    # Setup matplotlib graphs
    fig, ax1, ax2 = setup_graphs(cgroup_name)
    
    # Start animation
    ani = animation.FuncAnimation(
        fig, 
        update_graphs, 
        fargs=(collector, cgroup_id, ax1, ax2),
        interval=500,  # Update every 500ms
        blit=False
    )
    
    # Show the plot
    plt.show()

