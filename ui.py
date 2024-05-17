# ui.py

import os
from cryptography.fernet import Fernet
from client import generate_key, encrypt_message, decrypt_message

def display_menu():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("1. Show Connected Users")
    print("2. Start Messaging")
    print("3. Exit")

def show_connected_users(client_socket):
    client_socket.send("show_connected_users".encode())
    response = client_socket.recv(1024).decode()
    print("Connected Users:")
    print(response)
    input("\nPress Enter to return to the menu...")

def start_messaging(client_socket):
    recipient_username = input("Enter username to start messaging: ")
    client_socket.send(f"start_messaging:{recipient_username}".encode())
    response = client_socket.recv(1024).decode()
    if response == "request_accepted":
        print("Messaging session started with", recipient_username)
        chat_session(client_socket)
    elif response == "request_rejected":
        print("Messaging request rejected.")
    else:
        print("User not available.")
    input("\nPress Enter to return to the menu...")

def chat_session(client_socket):
    key = generate_key()
    print("Key:", key.decode())
    while True:
        message = input("You: ")
        if message == 'exit':
            client_socket.send(message.encode())
            break
        encrypted_message = encrypt_message(key, message)
        client_socket.send(encrypted_message)

def start_ui(client_socket, username):
    while True:
        display_menu()
        choice = input("Enter choice: ")
        if choice == '1':
            show_connected_users(client_socket)
        elif choice == '2':
            start_messaging(client_socket)
        elif choice == '3':
            client_socket.send('exit'.encode())
            client_socket.close()
            exit()
        else:
            print("Invalid choice. Please try again.")
