import socket
import threading
import time
import math
import os

# -----------------------------
# Configuration
# -----------------------------
SERVER = ("127.0.0.1", 9000)
RUN_SECONDS = 60

CPU_THREADS = os.cpu_count() or 2

MEMORY_MB = 300            # Total memory to allocate
MEMORY_CHUNK_MB = 10       # Allocate gradually

UPLOAD_CHUNK = b"a" * 65536  # 64 KB
RECV_SIZE = 65536

PRINT_INTERVAL = 1.0


# -----------------------------
# Shared state
# -----------------------------
stop_flag = False
bytes_sent = 0
bytes_received = 0


# -----------------------------
# CPU worker
# -----------------------------
def cpu_worker():
    x = 0.0001
    while not stop_flag:
        x = math.sin(x) * math.cos(x) * math.sqrt(abs(x))
        if x == 0:
            x = 0.0001


# -----------------------------
# Memory worker
# -----------------------------
def memory_worker():
    allocated = []
    allocated_mb = 0

    try:
        while not stop_flag and allocated_mb < MEMORY_MB:
            chunk = bytearray(MEMORY_CHUNK_MB * 1024 * 1024)
            # Touch memory so it is actually committed
            for i in range(0, len(chunk), 4096):
                chunk[i] = 1

            allocated.append(chunk)
            allocated_mb += MEMORY_CHUNK_MB
            time.sleep(0.1)

        # Hold memory until stopped
        while not stop_flag:
            time.sleep(1)

    except MemoryError:
        pass


# -----------------------------
# Network worker
# -----------------------------
def network_worker():
    global bytes_sent, bytes_received

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(SERVER)
        s.settimeout(2.0)

        while not stop_flag:
            try:
                s.sendall(UPLOAD_CHUNK)
                bytes_sent += len(UPLOAD_CHUNK)

                data = s.recv(RECV_SIZE)
                if not data:
                    break
                bytes_received += len(data)

            except socket.timeout:
                continue
            except Exception:
                break


# -----------------------------
# Stats printer
# -----------------------------
def stats_worker(start_time):
    last_print = start_time

    while not stop_flag:
        now = time.time()
        if now - last_print >= PRINT_INTERVAL:
            elapsed = now - start_time
            progress = min(100.0, (elapsed / RUN_SECONDS) * 100)

            print(
                f"[STATS] {progress:5.1f}% | "
                f"Sent: {bytes_sent / (1024*1024):7.2f} MB | "
                f"Recv: {bytes_received / (1024*1024):7.2f} MB"
            )

            last_print = now

        time.sleep(0.1)


# -----------------------------
# Main
# -----------------------------
def main():
    global stop_flag

    print("[CLIENT] Starting full resource stress test")
    print(f"[CLIENT] Duration      : {RUN_SECONDS}s")
    print(f"[CLIENT] CPU threads   : {CPU_THREADS}")
    print(f"[CLIENT] Memory target : {MEMORY_MB} MB\n")

    start_time = time.time()
    end_time = start_time + RUN_SECONDS

    threads = []

    # CPU threads
    for _ in range(CPU_THREADS):
        t = threading.Thread(target=cpu_worker, daemon=True)
        t.start()
        threads.append(t)

    # Memory thread
    mem_t = threading.Thread(target=memory_worker, daemon=True)
    mem_t.start()
    threads.append(mem_t)

    # Network thread
    net_t = threading.Thread(target=network_worker, daemon=True)
    net_t.start()
    threads.append(net_t)

    # Stats thread
    stats_t = threading.Thread(target=stats_worker, args=(start_time,), daemon=True)
    stats_t.start()

    # Run
    try:
        while time.time() < end_time:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass

    stop_flag = True
    time.sleep(2)

    total_time = time.time() - start_time

    print("\n[CLIENT] Finished")
    print(f"  Duration       : {total_time:.2f} seconds")
    print(f"  Total sent     : {bytes_sent / (1024*1024):.2f} MB")
    print(f"  Total received : {bytes_received / (1024*1024):.2f} MB")


if __name__ == "__main__":
    main()
