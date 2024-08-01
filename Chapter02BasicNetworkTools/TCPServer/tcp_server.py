import socket
import threading

def handle_client(client_socket: socket.socket):
    with client_socket as client_socket:
        request = client_socket.recv(1024)

        print(f"[*] Received {request.decode("utf-8")}")

        client_socket.send(b"ACK")

def main():
    SERVER_IP = "0.0.0.0"
    SERVER_PORT = 9998
    MAX_CONNECTIONS = 5

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((SERVER_IP, SERVER_PORT))
    server.listen(MAX_CONNECTIONS)

    print(f"[*] Server listening on {SERVER_IP}:{SERVER_PORT}")

    while True:
        client, address = server.accept()

        print(f"[*] Connection accepted from {address[0]}:{address[1]}")

        client_handler = threading.Thread(target=handle_client, args=(client,))
        client_handler.start()

if __name__ == "__main__":
    main()