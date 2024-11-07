import argparse

from utils.constants import (
    DEFAULT_DELAY_MS,
    DEFAULT_END_PORT,
    DEFAULT_START_PORT,
    MAX_THREADS,
)


class Parser:
    def __init__(self):
        parser = argparse.ArgumentParser(description="Port Scanner")
        parser.add_argument("target", help="Target IP address to scan.")
        parser.add_argument(
            "--start",
            "-s",
            type=int,
            default=DEFAULT_START_PORT,
            help=f"Starting Port (default: {DEFAULT_START_PORT})",
        )

        parser.add_argument(
            "--end",
            "-e",
            type=int,
            default=DEFAULT_END_PORT,
            help=f"Ending Port (default: {DEFAULT_END_PORT})",
        )

        parser.add_argument(
            "--delay",
            "-d",
            type=int,
            default=DEFAULT_DELAY_MS,
            help=f"Delay between scans (ms) (default: {DEFAULT_DELAY_MS})",
        )

        parser.add_argument(
            "--threads",
            "-t",
            type=int,
            default=MAX_THREADS,
            help=f"Max threads used to send packets (default: {DEFAULT_DELAY_MS})",
        )

        args = parser.parse_args()

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
            f"Delay: {self.delay}\n"
            f"Max Threads: {self.max_threads}\n"
        )

    def __repr__(self):
        return self.__str__()
