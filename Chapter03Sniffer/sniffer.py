import socket
import os

HOST = "10.0.2.15"
ON_WINDOWS = os.name == "nt"


def main():
    if ON_WINDOWS:
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    address = (HOST, 0)

    sniffer.bind(address)
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if ON_WINDOWS:
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print(sniffer.recvfrom(65565))

    if ON_WINDOWS:
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


if __name__ == "__main__":
    main()
