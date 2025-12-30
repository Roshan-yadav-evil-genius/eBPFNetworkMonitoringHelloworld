import socket
import threading
import time
import sys

# Bind to all interfaces (0.0.0.0) to allow connections from other systems
# Use "127.0.0.1" for localhost-only, or specific IP for a particular interface
HOST = "0.0.0.0"  # Listen on all network interfaces
PORT = 9000
CHUNK = b"x" * 65536  # 64 KB
CHUNK_SIZE = len(CHUNK)


def handle_client(conn, client_id):
    try:
        start_time = time.time()
        iteration = 0
        bytes_sent = 0
        bytes_received = 0
        last_print_time = start_time
        print_interval = 1.0  # Print every 1 second
        
        print(f"[SERVER] Client {client_id} connected")
        
        while True:
            # Receive data first (RX on server, TX from client)
            data = conn.recv(65536)
            if not data:
                break
            bytes_received += len(data)

            # Then send data (TX from server, RX on client)
            conn.sendall(CHUNK)
            bytes_sent += CHUNK_SIZE
            
            iteration += 1
            current_time = time.time()
            
            # Print progress periodically
            if current_time - last_print_time >= print_interval:
                elapsed = current_time - start_time
                mb_sent = bytes_sent / (1024 * 1024)
                mb_received = bytes_received / (1024 * 1024)
                
                print(f"[SERVER] Client {client_id} | "
                      f"Iterations: {iteration} | "
                      f"Sent: {mb_sent:.2f} MB | "
                      f"Received: {mb_received:.2f} MB | "
                      f"Time: {elapsed:.1f}s")
                last_print_time = current_time
                
    except Exception as e:
        print(f"[SERVER] Client {client_id} error: {e}")
    finally:
        conn.close()
        print(f"[SERVER] Client {client_id} disconnected")


def get_local_ip():
    """Get the local IP address of this machine."""
    try:
        # Connect to a remote address to determine local IP
        # (doesn't actually send data)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "unknown"


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()

        local_ip = get_local_ip()
        print("=" * 60)
        print(f"Dummy server listening on {HOST}:{PORT}")
        print(f"Local IP address: {local_ip}")
        print(f"Connect from other systems using: {local_ip}:{PORT}")
        print("=" * 60)
        print("\nNote: Make sure firewall allows incoming connections on port 9000")
        print("      Ubuntu/Debian: sudo ufw allow 9000/tcp")
        print("      RHEL/Fedora:   sudo firewall-cmd --add-port=9000/tcp --permanent")
        print("=" * 60)
        print()
        
        client_counter = 0

        while True:
            conn, addr = s.accept()
            client_counter += 1
            print(f"[SERVER] New connection from {addr[0]}:{addr[1]} (Client {client_counter})")
            threading.Thread(
                target=handle_client, daemon=True, args=(conn, client_counter)
            ).start()


if __name__ == "__main__":
    main()
