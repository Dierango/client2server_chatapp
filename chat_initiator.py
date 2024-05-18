import socket
import json
import threading
import time
import os
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

# Constants
CHAT_PORT = 6001
PORT = 6000

discovered_users = {}

def get_current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_message(username, message, sent=True):
    with open("chat_history.log", "a") as file:
        status = "SENT" if sent else "RECEIVED"
        file.write(f"{get_current_time()} {username} {status} {message}\n")

def load_peers():
    current_time = time.time()
    peers = {}
    for username, info in discovered_users.items():
        if current_time - info['timestamp'] < 15 * 60:
            status = "Online" if current_time - info['timestamp'] < 10 else "Away"
            peers[username] = (info['ip'], info['timestamp'])
    return peers

def display_users():
    peers = load_peers()
    current_time = time.time()
    for username, (ip, last_seen) in peers.items():
        status = "Online" if current_time - last_seen < 10 else "Away"
        print(f"{username} ({status})")

def send_message(s, public_key, username):
    while True:
        message = input("Enter your message (or type 'exit' to quit): ")
        if message.lower() == 'exit':
            break

        if public_key:  
            encrypted_message = public_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_message_base64 = base64.b64encode(encrypted_message).decode()
            s.sendall(json.dumps({"encrypted message": encrypted_message_base64}).encode())
        else:
            s.sendall(json.dumps({"unencrypted message": message}).encode())

        log_message(username, message, sent=True)

def receive_message(s, private_key, username):
    try:
        while True:
            data = s.recv(4096).decode()
            if not data:
                break

            message_json = json.loads(data)

            if 'encrypted message' in message_json:
                encrypted_message = base64.b64decode(message_json['encrypted message'])
                decrypted_message = private_key.decrypt(
                    encrypted_message,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                print(f"\nReceived encrypted message: {decrypted_message.decode()}")
                log_message(username, decrypted_message.decode(), sent=False)

            elif 'unencrypted message' in message_json:
                message = message_json['unencrypted message']
                print(f"\nReceived unencrypted message: {message}")
                log_message(username, message, sent=False)

    except Exception as e:
        print(f"Error receiving message: {e}")

def initiate_chat(username, secure):
    peers = load_peers()
    if username not in peers:
        print("User not found.")
        return

    peer_ip = peers[username][0]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((peer_ip, CHAT_PORT))

            if secure:
                local_private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )
                local_public_key = local_private_key.public_key()
                public_pem = local_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

                s.sendall(json.dumps({'key': base64.b64encode(public_pem).decode()}).encode())

                response = s.recv(4096)
                response_data = json.loads(response.decode())
                peer_public_key_pem = base64.b64decode(response_data['key'])
                peer_public_key = serialization.load_pem_public_key(
                    peer_public_key_pem,
                    backend=default_backend()
                )

                send_thread = threading.Thread(target=send_message, args=(s, peer_public_key, username))
                receive_thread = threading.Thread(target=receive_message, args=(s, local_private_key, username))
            else:
                send_thread = threading.Thread(target=send_message, args=(s, None, username))
                receive_thread = threading.Thread(target=receive_message, args=(s, None, username))

            send_thread.start()
            receive_thread.start()

            send_thread.join()
            receive_thread.join()

    except Exception as e:
        print(f"Could not establish connection with {username}. Error: {e}")

def display_history():
    if not os.path.exists("chat_history.log"):
        print("No chat history found.")
        return
    
    with open("chat_history.log", "r") as file:
        for line in file:
            print(line.strip())

def listen_for_broadcast():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', PORT))

        while True:
            data, addr = sock.recvfrom(1024)
            message = data.decode('utf-8')
            try:
                message_json = json.loads(message)
                if 'username' in message_json:
                    discovered_users[message_json['username']] = {"ip": addr[0], "timestamp": time.time()}
            except json.JSONDecodeError:
                print("Failed to decode JSON from broadcast.")

def start_peer_discovery_thread():
    thread = threading.Thread(target=listen_for_broadcast)
    thread.daemon = True
    thread.start()

def main():
    start_peer_discovery_thread()
    
    while True:
        choice = input("Choose action: Users, Chat, History, or Exit: ").strip().lower()
        if choice == "users":
            display_users()
        elif choice == "chat":
            username = input("Enter the username to chat with: ")
            secure = input("Secure chat (yes/no)? ").strip().lower() == "yes"
            initiate_chat(username, secure)
        elif choice == "history":
            display_history()
        elif choice == "exit":
            break
        else:
            print("Invalid choice, try again.")

if __name__ == "__main__":
    main()