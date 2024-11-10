import argparse
import ipaddress
import sys

from utils.constants import (
    DEFAULT_DELAY_MS,
    DEFAULT_END_PORT,
    DEFAULT_START_PORT,
    MAX_THREADS,
)


class Parser:
    def __init__(self):
        parser = argparse.ArgumentParser(description="Port Scanner")
        parser.add_argument(
            "target", type=validate_ipv4, help="Target IP address to scan."
        )

        parser.add_argument(
            "--start",
            "-s",
            type=validate_port,
            default=DEFAULT_START_PORT,
            help=f"Starting Port (default: {DEFAULT_START_PORT})",
        )

        parser.add_argument(
            "--end",
            "-e",
            type=validate_port,
            default=DEFAULT_END_PORT,
            help=f"Ending Port (default: {DEFAULT_END_PORT})",
        )

        parser.add_argument(
            "--delay",
            "-d",
            type=lambda x: validate_greater_than(x, 0),
            default=DEFAULT_DELAY_MS,
            help=f"Delay between port scans (ms) (default: {DEFAULT_DELAY_MS})",
        )

        parser.add_argument(
            "--threads",
            "-t",
            type=lambda x: validate_greater_than(x, 1),
            default=MAX_THREADS,
            help=f"Max threads used to send packets (default: {MAX_THREADS})",
        )

        args = parser.parse_args()

        if args.start > args.end:
            sys.exit("Starting port cannot be greater than ending port.")

        delay_sec = args.delay / 1000
        self.start_port: int = args.start
        self.end_port: int = args.end
        # Delay in seconds
        self.delay: int = delay_sec
        self.target: str = args.target
        self.max_threads: int = args.threads

    def __str__(self):
        return (
            f"Target: {self.target}\n"
            f"Start Port: {self.start_port}\n"
            f"End Port: {self.end_port}\n"
            f"Delay (sec): {self.delay}\n"
            f"Max Threads: {self.max_threads}\n"
        )

    def __repr__(self):
        return self.__str__()


def validate_port(value):
    try:
        port = int(value)
        if not 0 < port < 65535:
            raise ValueError
        return port
    except:
        sys.exit(
            f"Invalid port number: {value}. Port needs to be an integer between 1 and 65535"
        )


def validate_ipv4(value):
    try:
        ip = ipaddress.ip_address(str(value))
        if not ip.version == 4:
            raise ValueError
        return str(value)
    except:
        sys.exit(f"Invalid IPv4 address format: {value}.")


def validate_greater_than(value, min: int):
    try:
        num = int(value)
        if num < min:
            raise ValueError
        return num
    except:
        sys.exit(
            f"Invalid number {value}. Value needs to be an integer greater than or equal to {min}."
        )
