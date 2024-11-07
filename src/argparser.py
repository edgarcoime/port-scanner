import argparse

from utils.constants import DEFAULT_DELAY_MS, DEFAULT_END_PORT, DEFAULT_START_PORT


class Parser:
    def __init__(self):
        default_start_port = DEFAULT_START_PORT
        default_end_port = DEFAULT_END_PORT
        default_delay_ms = DEFAULT_DELAY_MS

        parser = argparse.ArgumentParser(description="Port Scanner")
        parser.add_argument("target", help="Target IP address to scan.")
        parser.add_argument(
            "--start",
            "-s",
            type=int,
            default=default_start_port,
            help=f"Starting Port (default: {default_start_port})",
        )

        parser.add_argument(
            "--end",
            "-e",
            type=int,
            default=default_end_port,
            help=f"Ending Port (default: {default_end_port})",
        )

        parser.add_argument(
            "--delay",
            "-d",
            type=int,
            default=default_delay_ms,
            help=f"Delay between scans (ms) (default: {default_delay_ms})",
        )

        args = parser.parse_args()

        delay_sec = args.delay / 1000

        self.start_port: int = args.start
        self.end_port: int = args.end
        # Delay in seconds
        self.delay: int = delay_sec
        self.target: str = args.target

    def __str__(self):
        return f"Target: {self.target}, Start Port: {self.start_port}, End Port: {self.end_port}, Delay: {self.delay}"

    def __repr__(self):
        return f"Target: {self.target}, Start Port: {self.start_port}, End Port: {self.end_port}, Delay: {self.delay}"
