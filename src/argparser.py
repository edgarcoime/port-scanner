import argparse


class Parser:
    def __init__(self):
        DEFAULT_START = 1
        DEFAULT_END = 65535
        DEFAULT_DELAY = 0

        parser = argparse.ArgumentParser(description="Port Scanner")
        parser.add_argument("target", help="Target IP address to scan.")
        parser.add_argument(
            "--start",
            "-s",
            type=int,
            default=DEFAULT_START,
            help=f"Starting Port (default: {DEFAULT_START})",
        )

        parser.add_argument(
            "--end",
            "-e",
            type=int,
            default=DEFAULT_END,
            help=f"Ending Port (default: {DEFAULT_END})",
        )

        parser.add_argument(
            "--delay",
            "-d",
            type=int,
            default=DEFAULT_DELAY,
            help=f"Delay between scans (default: {DEFAULT_DELAY})",
        )

        args = parser.parse_args()
        self.start_port = args.start
        self.end_port = args.end
        self.delay = args.delay
        self.target = args.target

    def __str__(self):
        return f"Target: {self.target}, Start Port: {self.start_port}, End Port: {self.end_port}, Delay: {self.delay}"
