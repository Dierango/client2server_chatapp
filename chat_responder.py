import socket
import json
import threading
from datetime import datetime
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

# Constants
LISTEN_PORT = 6001  # Port on which the Chat Responder will listen for incoming connections

def get_current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_message(sender, message, received=True):
    with open("chat_history.log", "a") as file:
        status = "RECEIVED" if received else "SENT"
        file.write(f"{get_current_time()} {sender} {status} {message}\n")

def handle_client_connection(client_socket, client_address):
    try:
        # Initialize variables to determine if the session is secure
        private_key = None
        public_key = None
        peer_public_key = None

        # Receive the initial message which might be a key or a direct message
        data = client_socket.recv(4096).decode()
        message_json = json.loads(data)

        # Check if this is a key exchange message
        if 'key' in message_json:
            # Generate RSA keys for this session
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            public_key = private_key.public_key()

            # Decode the peer's public key
            peer_public_key = serialization.load_pem_public_key(
                base64.b64decode(message_json['key']),
                backend=default_backend()
            )

            # Send our public key to the initiator
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            client_socket.sendall(json.dumps({'key': base64.b64encode(public_pem).decode()}).encode())

            # Start threads for sending and receiving messages
            send_thread = threading.Thread(target=send_message, args=(client_socket, peer_public_key, 'Responder'))
            receive_thread = threading.Thread(target=receive_message, args=(client_socket, private_key, 'Responder'))
        else:
            # If no key exchange, it's an unsecured session
            if 'unencrypted message' in message_json:
                print(f"\nReceived unencrypted message: {message_json['unencrypted message']}")
                log_message(client_address[0], message_json['unencrypted message'], received=True)

            # Start unsecured communication threads
            send_thread = threading.Thread(target=send_message_unsecured, args=(client_socket, 'Responder'))
            receive_thread = threading.Thread(target=receive_message_unsecured, args=(client_socket, 'Responder'))

        # Start the threads
        send_thread.start()
        receive_thread.start()

        # Wait for both threads to finish
        send_thread.join()
        receive_thread.join()

    except Exception as e:
        print(f"Error handling connection from {client_address}: {e}")
    finally:
        client_socket.close()

def send_message(s, peer_public_key, sender):
    """Handles sending encrypted messages."""
    try:
        while True:
            message = input("Enter your message (or type 'exit' to quit): ")
            if message.lower() == 'exit':
                break

            # Encrypt the message using the peer's public key
            encrypted_message = peer_public_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_message_base64 = base64.b64encode(encrypted_message).decode()

            # Send the encrypted message
            s.sendall(json.dumps({"encrypted message": encrypted_message_base64}).encode())
            log_message(sender, message, received=False)

    except Exception as e:
        print(f"Error sending message: {e}")

def receive_message(s, private_key, sender):
    """Handles receiving encrypted messages."""
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
                log_message(sender, decrypted_message.decode(), received=True)

    except Exception as e:
        print(f"Error receiving message: {e}")

def send_message_unsecured(s, sender):
    """Handles sending unencrypted messages."""
    try:
        while True:
            message = input("Enter your message (or type 'exit' to quit): ")
            if message.lower() == 'exit':
                break

            # Send the unencrypted message
            s.sendall(json.dumps({"unencrypted message": message}).encode())
            log_message(sender, message, received=False)

    except Exception as e:
        print(f"Error sending message: {e}")

def receive_message_unsecured(s, sender):
    """Handles receiving unencrypted messages."""
    try:
        while True:
            data = s.recv(4096).decode()
            if not data:
                break

            message_json = json.loads(data)

            if 'unencrypted message' in message_json:
                message = message_json['unencrypted message']
                print(f"\nReceived unencrypted message: {message}")
                log_message(sender, message, received=True)

    except Exception as e:
        print(f"Error receiving message: {e}")

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', LISTEN_PORT))
    server.listen(5)
    print(f"Chat Responder is listening on port {LISTEN_PORT}...")

    try:
        while True:
            client_sock, address = server.accept()
            print(f"Accepted connection from {address[0]}:{address[1]}")
            client_handler = threading.Thread(
                target=handle_client_connection,
                args=(client_sock, address)
            )
            client_handler.start()
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        server.close()

if __name__ == "__main__":
    start_server()