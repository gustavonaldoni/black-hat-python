import sys


def integer_is_printable(number: int) -> bool:
    return len(repr(chr(number))) == 3


def printables(number: int) -> str:
    filter = [chr(i) if integer_is_printable(i) else "." for i in range(number)]
    return "".join(filter)


def hexdump(data, length=16, print_result=True) -> None | list[str]:
    hex_filter = printables(256)
    lines = []

    if isinstance(data, bytes):
        data = data.decode(errors="ignore")

    for i in range(0, len(data), length):
        word = str(data[i : i + length])

        printable = word.translate(hex_filter)
        hexa = " ".join([f"{ord(character):02X}" for character in word])
        hex_length = length * 3

        lines.append(f"{i:04x} {hexa:<{hex_length}} {printable}")

    if print_result:
        for line in lines:
            print(line)

    else:
        return lines


def main():
    file_path = sys.argv[1]

    buffer = b""

    with open(file_path, "rb") as file:
        buffer = file.read()

    hexdump(buffer)


if __name__ == "__main__":
    main()
