# server.py

import socket
import threading
from cryptography.fernet import Fernet

clients = {}
addresses = {}
keys = {}

def generate_key():
    return Fernet.generate_key()

def handle_client(client_socket, addr):
    try:
        username = client_socket.recv(1024).decode()
        clients[username] = client_socket
        addresses[username] = addr
        keys[username] = generate_key()
        print(f"{username} connected from {addr}")

        while True:
            message = client_socket.recv(1024).decode()
            if message == "show_connected_users":
                send_user_list(client_socket)
            elif message.startswith("start_messaging:"):
                recipient_username = message.split(":")[1]
                handle_messaging_request(client_socket, username, recipient_username)
            else:
                broadcast(f"{username}: {message}", exclude=username)
    except Exception as e:
        print(f"Error: {e}")
        remove_client(username)
    finally:
        client_socket.close()

def broadcast(message, exclude=None):
    for username, client in clients.items():
        if username != exclude:
            try:
                client.send(message.encode())
            except:
                remove_client(username)

def send_user_list(client_socket):
    users = ", ".join(clients.keys())
    client_socket.send(f"Connected users: {users}".encode())

def handle_messaging_request(client_socket, sender, recipient):
    if recipient in clients:
        recipient_socket = clients[recipient]
        try:
            recipient_socket.send(f"{sender} wants to start messaging with you. Accept? (Y/N)".encode())
            response = recipient_socket.recv(1024).decode()
            if response.upper() == "Y":
                client_socket.send("request_accepted".encode())
                recipient_socket.send("request_accepted".encode())
                chat_session(client_socket, recipient_socket, sender, recipient)
            else:
                client_socket.send("request_rejected".encode())
        except:
            client_socket.send("user_not_available".encode())
    else:
        client_socket.send("user_not_available".encode())

def chat_session(client_socket, recipient_socket, sender, recipient):
    while True:
        try:
            message = client_socket.recv(1024).decode()
            if message == 'exit':
                break
            recipient_socket.send(f"{sender}: {message}".encode())
            response = recipient_socket.recv(1024).decode()
            if response == 'exit':
                break
            client_socket.send(f"{recipient}: {response}".encode())
        except:
            break

def remove_client(username):
    if username in clients:
        client_socket = clients.pop(username)
        addresses.pop(username, None)
        keys.pop(username, None)
        print(f"{username} disconnected.")
        broadcast(f"{username} has left the chat.")

def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 5000))
    server_socket.listen(5)
    print("Server started on port 5000")

    while True:
        client_socket, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(client_socket, addr)).start()

if __name__ == "__main__":
    server()
