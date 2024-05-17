import socket
import threading

def announce_service():
    announce_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    announce_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    response_message = b"PEER_HERE"

    def listen_for_discovery():
        while True:
            try:
                data, addr = announce_socket.recvfrom(1024)
                if data.decode() == "DISCOVER_PEERS":
                    announce_socket.sendto(response_message, addr)
            except socket.timeout:
                continue

    announce_thread = threading.Thread(target=listen_for_discovery)
    announce_thread.daemon = True
    announce_thread.start()
