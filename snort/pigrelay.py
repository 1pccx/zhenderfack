import socket
import os
import time

SOCKFILE = "/tmp/snort_alert"

CONTROLLER_IP = "192.168.8.132"
CONTROLLER_PORT = 51234


if os.path.exists(SOCKFILE):
    os.unlink(SOCKFILE)

unsock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
unsock.bind(SOCKFILE)

print("[*] Pigrelay started")


def connect_controller():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Enable TCP Keepalive to prevent VMware NAT from dropping idle connections
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            # Send keepalive probe after 3 seconds of idleness, retry 3 times every 3 seconds
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 3)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 3)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            
            s.connect((CONTROLLER_IP, CONTROLLER_PORT))
            print(f"[*] Connected to Ryu {CONTROLLER_IP}:{CONTROLLER_PORT}")
            return s
        except Exception as e:
            print(f"[!] Connect failed: {e}, retrying...")
            time.sleep(2)


sock = connect_controller()

while True:
    data = unsock.recv(65863)

    if data:
        try:
            sock.sendall(data)
        except Exception as e:
            print(f"[!] Send failed: {e}, reconnecting...")
            try:
                sock.close()
            except Exception:
                pass

            sock = connect_controller()
            sock.sendall(data)