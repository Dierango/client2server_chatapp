# main.py

import sys
from client import client
from ui import start_ui

def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py [server|client]")
        sys.exit(1)

    if sys.argv[1] == 'server':
        from server import server
        server()
    elif sys.argv[1] == 'client':
        server_ip = input("Enter server IP: ")
        username, client_socket = client(server_ip)
        start_ui(client_socket, username)
    else:
        print("Invalid option. Use 'server' or 'client'")
        sys.exit(1)

if __name__ == "__main__":
    main()
