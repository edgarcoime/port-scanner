from argparser import Parser
from portscanner import PortScanner


def main():
    parser = Parser()
    scanner = PortScanner(parser)
    print(scanner)
    scanner.scan()


if __name__ == "__main__":
    main()
