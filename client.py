# client.py

import socket
import threading
from cryptography.fernet import Fernet

def generate_key():
    return Fernet.generate_key()

def encrypt_message(key, message):
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(message.encode())

def decrypt_message(key, encrypted_message):
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(encrypted_message).decode()

def client(server_ip):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, 5000))
    username = input("Enter your username: ")
    client_socket.send(username.encode())

    threading.Thread(target=listen_for_messages, args=(client_socket,)).start()

    return username, client_socket

def listen_for_messages(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode()
            if message:
                print(f"\n{message}")
                if message.endswith("(Y/N)"):
                    response = input()
                    client_socket.send(response.encode())
        except:
            break
