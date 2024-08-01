import socket


def main():
    host = "0.0.0.0"
    port = 9998

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    client.send(b"ABCDEF")

    response = client.recv(4096)

    print(response.decode())

    client.close()


if __name__ == "__main__":
    main()
