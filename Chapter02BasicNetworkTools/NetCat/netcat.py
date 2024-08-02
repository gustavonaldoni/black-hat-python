import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading


def execute(command: str) -> str:
    command = command.strip()

    if not command:
        return

    output = subprocess.check_output(shlex.split(command), stderr=subprocess.STDOUT)

    return output.decode()


class NetCat:
    def __init__(self, args, buffer=None) -> None:
        self.args = args
        self.buffer = buffer

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def handle_client(self, client_socket: socket.socket):
        MAX_FILE_BUFFER_RECEIVE = 4096
        MAX_COMMAND_BUFFER_RECEIVE = 64

        if self.args.execute:
            output = execute(self.args.execute)
            client_socket.send(output)

        elif self.args.upload:
            file_buffer = b""

            while True:
                data = client_socket.recv(MAX_COMMAND_BUFFER_RECEIVE)

                if data:
                    file_buffer += data
                else:
                    break

            with open(self.args.upload, "wb") as file:
                file.write(file_buffer)

            message = f"File saved {self.args.upload}"
            client_socket.send(message.encode())

        elif self.args.command:
            command_buffer = b""

            while True:
                try:
                    client_socket.send(b"<BHP: #> ")

                    while "\n" not in command_buffer.decode():
                        command_buffer += client_socket.recv(MAX_FILE_BUFFER_RECEIVE)

                    response = execute(command_buffer.decode())

                    if response:
                        client_socket.send(response.encode())

                    command_buffer = b""

                except Exception as e:
                    print(f"Server ended {e}")

                    self.socket.close()
                    sys.exit()

    def listen(self):
        MAX_CONNECTIONS = 5

        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(MAX_CONNECTIONS)

        while True:
            client_socket, client_address = self.socket.accept()

            client_thread = threading.Thread(
                target=self.handle_client, args=(client_socket,)
            )
            client_thread.start()

    def send(self):
        MAX_SEND_SIZE = 4096

        self.socket.connect((self.args.target, self.args.port))

        if self.buffer:
            self.socket.send(self.buffer)

        try:
            while True:
                receive_length = 1
                response = ""

                while receive_length:
                    data = self.socket.recv(MAX_SEND_SIZE)
                    receive_length = len(data)

                    response += data.decode()

                    if receive_length < MAX_SEND_SIZE:
                        break

                if response:
                    print(response)

                    buffer = input("> ")
                    buffer += "\n"

                    self.socket.send(buffer.encode())

        except KeyboardInterrupt:
            print("Interrupted by the user.")

            self.socket.close()
            sys.exit()

    def run(self) -> None:
        is_listener = self.args.listen

        if is_listener:
            self.listen()

        else:
            self.send()


def main():
    epilog = """Example:
    netcat.py -t 192.168.1.108 -p 5555 -l -c # command shell
    netcat.py -t 192.168.1.108 -p 5555 -l -u=mytest.txt # file upload
    netcat.py -t 192.168.1.108 -p 5555 -l -e=\"cat /etc/passwd\" # execute command
    echo 'ABC' | ./netcat.py -t 192.168.1.108 -p 105 # send text to server on port 105
    netcat.py -t 192.168.1.108 -p 5555 # connect to the server"""

    parser = argparse.ArgumentParser(
        description="BHP Networking Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(epilog),
    )

    parser.add_argument("-c", "--command", action="store_true", help="command shell")
    parser.add_argument("-e", "--execute", help="execute specified command")
    parser.add_argument("-l", "--listen", action="store_true", help="listen")
    parser.add_argument("-p", "--port", type=int, default=5555, help="specified port")
    parser.add_argument("-t", "--target", default="192.168.1.203", help="specified IP")
    parser.add_argument("-u", "--upload", help="upload a file")

    args = parser.parse_args()

    is_listener = args.listen

    if is_listener:
        buffer = ""

    else:
        buffer = sys.stdin.read()

    netcat = NetCat(args, buffer.encode())
    netcat.run()


if __name__ == "__main__":
    main()
