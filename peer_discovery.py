import socket
import json
import time
import threading
from datetime import datetime

# Constants
PORT = 6000  # Listening port, must match the service_announcer port

# Dictionary to store discovered users
discovered_users = {}

def listen_for_broadcast():
    """Listens for broadcast messages and updates the discovered_users dictionary."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # Allow reusing socket addresses
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', PORT))
        print("Peer Discovery is listening for broadcast messages...")

        while True:
            data, addr = sock.recvfrom(1024)
            message = data.decode('utf-8')
            try:
                message_json = json.loads(message)
                if 'username' in message_json:
                    username = message_json['username']
                    # Update the discovered users with the latest timestamp
                    discovered_users[username] = {"ip": addr[0], "timestamp": time.time()}
                    print(f"Detected user: {username} ({addr[0]})")
            except json.JSONDecodeError:
                print("Error: Invalid JSON format")

def start_peer_discovery_thread():
    """Starts the peer discovery in a separate thread."""
    thread = threading.Thread(target=listen_for_broadcast)
    thread.daemon = True  # Daemonize thread
    thread.start()

def load_peers():
    """Returns a dictionary of peers that have been active within the last 15 minutes."""
    current_time = time.time()
    recent_peers = {}
    for username, info in discovered_users.items():
        if current_time - info['timestamp'] < 15 * 60:  # 15 minutes
            status = "Online" if current_time - info['timestamp'] < 10 else "Away"
            recent_peers[username] = (info['ip'], status)
    return recent_peers

def display_users():
    peers = load_peers()
    for username, (ip, status) in peers.items():
        print(f"{username} ({status})")

def main():
    start_peer_discovery_thread()
    # Continue the rest of the application logic here
    try:
        while True:
            # Print active users every 10 seconds for demonstration
            time.sleep(10)
            display_users()
    except KeyboardInterrupt:
        print("Shutting down.")

if __name__ == "__main__":
    main()