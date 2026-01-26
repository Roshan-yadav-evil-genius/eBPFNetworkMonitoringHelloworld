"""Simple Cgroup Monitor - Monitor a specific cgroup by name with matplotlib graphs."""

import sys
import os
import argparse
import time
import signal
from pathlib import Path
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib.ticker import FuncFormatter

from execute_inside_cgroup import main as stress_test_main

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

    def run_function_in_cgroup(cgroup_path: Path, func) -> int:
        """Fork and run a function inside the specified cgroup.
        
        Returns the child process PID to the parent process.
        """
        cgroup_procs = cgroup_path / "cgroup.procs"
        
        pid = os.fork()
        
        if pid == 0:
            # Child process - move self into cgroup, then run the function
            try:
                # Move this process into the cgroup
                with open(cgroup_procs, 'w') as f:
                    f.write(str(os.getpid()))
                print(f"✅ Child process {os.getpid()} moved into cgroup")
                
                # Now run the function inside the cgroup
                func()
                
            except PermissionError:
                print(f"❌ Permission denied: Cannot write to {cgroup_procs}")
                print("   Run with sudo to execute processes inside cgroups")
            except Exception as e:
                print(f"❌ Child process error: {e}")
            finally:
                os._exit(0)  # Exit child process
        else:
            # Parent process - return child PID for tracking
            print(f"✅ Started stress test process (PID: {pid}) inside cgroup '{cgroup_path.name}'")
            return pid

    # ==================== Cgroup Stats Reading Functions ====================

    def get_cpu_stats(cgroup_path: Path) -> dict:
        """Read CPU stats from cgroup filesystem."""
        cpu_stat_file = cgroup_path / "cpu.stat"
        stats = {
            "usage_usec": 0,
            "user_usec": 0,
            "system_usec": 0,
        }
        
        try:
            if cpu_stat_file.exists():
                with open(cpu_stat_file, 'r') as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            key = parts[0]
                            value = int(parts[1])
                            if key == "usage_usec":
                                stats["usage_usec"] = value
                            elif key == "user_usec":
                                stats["user_usec"] = value
                            elif key == "system_usec":
                                stats["system_usec"] = value
        except (FileNotFoundError, PermissionError, ValueError) as e:
            # If file doesn't exist or can't read, return zeros
            pass
        
        return stats

    def get_memory_stats(cgroup_path: Path) -> dict:
        """Read memory stats from cgroup filesystem."""
        memory_current_file = cgroup_path / "memory.current"
        memory_max_file = cgroup_path / "memory.max"
        
        stats = {
            "memory_used_bytes": 0,
            "memory_limit_bytes": None,  # None means unlimited
        }
        
        try:
            if memory_current_file.exists():
                with open(memory_current_file, 'r') as f:
                    stats["memory_used_bytes"] = int(f.read().strip())
        except (FileNotFoundError, PermissionError, ValueError):
            pass
        
        try:
            if memory_max_file.exists():
                with open(memory_max_file, 'r') as f:
                    limit_str = f.read().strip()
                    if limit_str == "max":
                        stats["memory_limit_bytes"] = None  # Unlimited
                    else:
                        stats["memory_limit_bytes"] = int(limit_str)
        except (FileNotFoundError, PermissionError, ValueError):
            pass
        
        return stats

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
        """Initialize matplotlib figure with four subplots in 2x2 grid."""
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle(f'Cgroup Monitor: {cgroup_name}', fontsize=14, fontweight='bold')
        
        # Network I/O subplot (top-left)
        ax1.set_title('Network I/O', fontweight='bold')
        ax1.set_xlabel('Time (samples)')
        ax1.set_ylabel('Bytes')
        ax1.grid(True, alpha=0.3)
        ax1.legend(loc='upper left')
        
        # CPU Usage subplot (top-right)
        ax2.set_title('CPU Usage', fontweight='bold')
        ax2.set_xlabel('Time (samples)')
        ax2.set_ylabel('CPU Usage (%)')
        ax2.grid(True, alpha=0.3)
        ax2.legend(loc='upper left')
        
        # File I/O subplot (bottom-left)
        ax3.set_title('File I/O', fontweight='bold')
        ax3.set_xlabel('Time (samples)')
        ax3.set_ylabel('Bytes')
        ax3.grid(True, alpha=0.3)
        ax3.legend(loc='upper left')
        
        # RAM Usage subplot (bottom-right)
        ax4.set_title('Memory Usage', fontweight='bold')
        ax4.set_xlabel('Time (samples)')
        ax4.set_ylabel('Bytes')
        ax4.grid(True, alpha=0.3)
        ax4.legend(loc='upper left')
        
        plt.tight_layout()
        return fig, ax1, ax2, ax3, ax4

    def update_graphs(frame, collector, cgroup_id, cgroup_path, ax1, ax2, ax3, ax4):
        """Update function for matplotlib animation."""
        # Get current stats from BPF
        stats = collector.get_stats_for_cgroup(cgroup_id)
        history = collector.get_history(cgroup_id)
        rates = _calculate_rates(history)
        
        # Read CPU and memory stats from cgroup filesystem
        cpu_stats = get_cpu_stats(cgroup_path)
        memory_stats = get_memory_stats(cgroup_path)
        
        # Track CPU and memory history (store in a simple list, max 100 entries)
        if not hasattr(update_graphs, 'cpu_history'):
            update_graphs.cpu_history = []
            update_graphs.memory_history = []
            update_graphs.prev_cpu_time = cpu_stats["usage_usec"]
            update_graphs.prev_wall_time = time.time()
            cpu_usage_percent = 0.0  # First call, no delta yet
        else:
            current_wall_time = time.time()
            wall_time_delta = current_wall_time - update_graphs.prev_wall_time
            
            # Calculate CPU usage percentage
            cpu_time_delta = cpu_stats["usage_usec"] - update_graphs.prev_cpu_time
            if wall_time_delta > 0 and cpu_time_delta >= 0:
                # CPU usage % = (CPU time delta / wall time delta) * 100
                # Convert microseconds to seconds
                cpu_usage_percent = (cpu_time_delta / 1_000_000.0 / wall_time_delta) * 100.0
            else:
                cpu_usage_percent = 0.0
            
            update_graphs.prev_cpu_time = cpu_stats["usage_usec"]
            update_graphs.prev_wall_time = current_wall_time
        
        current_wall_time = time.time()
        
        # Store in history (keep last 100 samples)
        cpu_data = {
            'usage_percent': cpu_usage_percent,
            'cpu_time_sec': cpu_stats["usage_usec"] / 1_000_000.0,
            'timestamp': current_wall_time
        }
        update_graphs.cpu_history.append(cpu_data)
        if len(update_graphs.cpu_history) > 100:
            update_graphs.cpu_history.pop(0)
        
        memory_data = {
            'used_bytes': memory_stats["memory_used_bytes"],
            'limit_bytes': memory_stats["memory_limit_bytes"],
            'timestamp': current_wall_time
        }
        update_graphs.memory_history.append(memory_data)
        if len(update_graphs.memory_history) > 100:
            update_graphs.memory_history.pop(0)
        
        if len(history) < 2:
            return
        
        # Prepare data
        samples = list(range(len(history)))
        rx_bytes = [s.rx_bytes for s in history]
        tx_bytes = [s.tx_bytes for s in history]
        read_bytes = [s.read_bytes for s in history]
        write_bytes = [s.write_bytes for s in history]
        
        # Prepare CPU data
        cpu_samples = list(range(len(update_graphs.cpu_history)))
        cpu_usage_percents = [d['usage_percent'] for d in update_graphs.cpu_history]
        cpu_times = [d['cpu_time_sec'] for d in update_graphs.cpu_history]
        
        # Prepare memory data
        memory_samples = list(range(len(update_graphs.memory_history)))
        memory_used = [d['used_bytes'] for d in update_graphs.memory_history]
        memory_limit = update_graphs.memory_history[-1]['limit_bytes'] if update_graphs.memory_history else None
        
        # Clear and update Network I/O graph (top-left)
        ax1.clear()
        ax1.plot(samples, rx_bytes, 'g-', label=f'RX ({_format_bytes(rates["rx_bytes_per_sec"])}/s)', linewidth=2)
        ax1.plot(samples, tx_bytes, 'orange', label=f'TX ({_format_bytes(rates["tx_bytes_per_sec"])}/s)', linewidth=2)
        ax1.set_title(f'Network I/O - RX: {_format_bytes(stats.rx_bytes)}, TX: {_format_bytes(stats.tx_bytes)}', fontweight='bold')
        ax1.set_xlabel('Time (samples)')
        ax1.set_ylabel('Bytes')
        ax1.grid(True, alpha=0.3)
        ax1.legend(loc='upper left')
        ax1.yaxis.set_major_formatter(FuncFormatter(lambda x, p: _format_bytes(x)))
        
        # Clear and update CPU Usage graph (top-right)
        ax2.clear()
        if len(cpu_samples) > 0:
            # CPU Usage % on left y-axis
            ax2.plot(cpu_samples, cpu_usage_percents, 'b-', label=f'CPU Usage ({cpu_usage_percent:.1f}%)', linewidth=2)
            ax2.set_ylabel('CPU Usage (%)', color='b')
            ax2.tick_params(axis='y', labelcolor='b')
            ax2.set_ylim(bottom=0)
            
            # CPU Time on right y-axis
            ax2_twin = ax2.twinx()
            ax2_twin.plot(cpu_samples, cpu_times, 'g--', label=f'CPU Time ({cpu_times[-1]:.1f}s)', linewidth=2, alpha=0.7)
            ax2_twin.set_ylabel('CPU Time (seconds)', color='g')
            ax2_twin.tick_params(axis='y', labelcolor='g')
            
            # Combine legends
            lines1, labels1 = ax2.get_legend_handles_labels()
            lines2, labels2 = ax2_twin.get_legend_handles_labels()
            ax2.legend(lines1 + lines2, labels1 + labels2, loc='upper left')
        
        ax2.set_title(f'CPU Usage - {cpu_usage_percent:.1f}% | Time: {cpu_times[-1] if cpu_times else 0:.1f}s', fontweight='bold')
        ax2.set_xlabel('Time (samples)')
        ax2.grid(True, alpha=0.3)
        
        # Clear and update File I/O graph (bottom-left)
        ax3.clear()
        ax3.plot(samples, read_bytes, 'b-', label=f'Read ({_format_bytes(rates["read_bytes_per_sec"])}/s)', linewidth=2)
        ax3.plot(samples, write_bytes, 'r-', label=f'Write ({_format_bytes(rates["write_bytes_per_sec"])}/s)', linewidth=2)
        ax3.set_title(f'File I/O - Read: {_format_bytes(stats.read_bytes)}, Write: {_format_bytes(stats.write_bytes)}', fontweight='bold')
        ax3.set_xlabel('Time (samples)')
        ax3.set_ylabel('Bytes')
        ax3.grid(True, alpha=0.3)
        ax3.legend(loc='upper left')
        ax3.yaxis.set_major_formatter(FuncFormatter(lambda x, p: _format_bytes(x)))
        
        # Clear and update RAM Usage graph (bottom-right)
        ax4.clear()
        if len(memory_samples) > 0:
            ax4.plot(memory_samples, memory_used, 'r-', label=f'Memory Used', linewidth=2)
            
            # Draw memory limit line if set
            if memory_limit is not None:
                ax4.axhline(y=memory_limit, color='gray', linestyle='--', linewidth=2, 
                           label=f'Limit ({_format_bytes(memory_limit)})', alpha=0.7)
                memory_percent = (memory_stats["memory_used_bytes"] / memory_limit * 100) if memory_limit > 0 else 0
                title_suffix = f' / {_format_bytes(memory_limit)} ({memory_percent:.1f}%)'
            else:
                title_suffix = ' / unlimited'
            
            ax4.set_title(f'Memory Usage - {_format_bytes(memory_stats["memory_used_bytes"])}{title_suffix}', fontweight='bold')
        else:
            ax4.set_title('Memory Usage - Collecting data...', fontweight='bold')
        
        ax4.set_xlabel('Time (samples)')
        ax4.set_ylabel('Bytes')
        ax4.grid(True, alpha=0.3)
        ax4.legend(loc='upper left')
        ax4.yaxis.set_major_formatter(FuncFormatter(lambda x, p: _format_bytes(x)))
        
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

    # Start stress test inside the cgroup
    print("🚀 Starting stress test inside cgroup...")
    child_pid = run_function_in_cgroup(cgroup_path, stress_test_main)

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
    fig, ax1, ax2, ax3, ax4 = setup_graphs(cgroup_name)
    
    # Start animation
    ani = animation.FuncAnimation(
        fig, 
        update_graphs, 
        fargs=(collector, cgroup_id, cgroup_path, ax1, ax2, ax3, ax4),
        interval=500,  # Update every 500ms
        blit=False
    )
    
    # Show the plot
    plt.show()

    # Cleanup: terminate child process when graph window closes
    print("\n🛑 Cleaning up...")
    if child_pid:
        try:
            os.kill(child_pid, signal.SIGTERM)
            os.waitpid(child_pid, 0)
            print(f"✅ Child process {child_pid} terminated")
        except ProcessLookupError:
            print(f"✅ Child process {child_pid} already exited")
        except Exception as e:
            print(f"⚠️ Error terminating child process: {e}")
