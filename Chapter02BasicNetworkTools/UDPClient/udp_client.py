import socket

def main():
    host = "127.0.0.1"
    port = 9997

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.sendto(b"AAABBBCCC", (host, port))

    data, address = client.recvfrom(4096)

    print(address)
    print(data.decode())
    client.close()

if __name__ == "__main__":
    main()