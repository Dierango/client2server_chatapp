import socket
import json
import time
from threading import Thread

# Constants
BROADCAST_IP = "255.255.255.255"  # Typical broadcast address; adjust if needed
PORT = 6000  # Must match the port used for listening in peer_discovery
INTERVAL = 5  # Interval in seconds between broadcasts

def broadcast_presence(username):
    """Broadcasts the presence of this user to the network."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # Set the socket option to enable broadcast
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        while True:
            # Prepare the message with the username
            message = json.dumps({"username": username})
            # Send the broadcast message
            sock.sendto(message.encode('utf-8'), (BROADCAST_IP, PORT))
            print(f"Broadcasting presence of {username}")
            # Wait for the next broadcast
            time.sleep(INTERVAL)

def start_service_announcer(username):
    """Starts the service announcer in a separate thread."""
    thread = Thread(target=broadcast_presence, args=(username,))
    thread.daemon = True  # Daemonize thread
    thread.start()

def main(username):
    start_service_announcer(username)
    # Placeholder for other operations; adjust as necessary
    try:
        while True:
            # Simulate doing other tasks
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down service announcer.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python service_announcer.py <username>")
    else:
        username = sys.argv[1]
        main(username)