import argparse


class Parser:
    def __init__(self):
        start_port = 1
        end_port = 65535
        delay_ms = 0

        parser = argparse.ArgumentParser(description="Port Scanner")
        parser.add_argument("target", help="Target IP address to scan.")
        parser.add_argument(
            "--start",
            "-s",
            type=int,
            default=start_port,
            help=f"Starting Port (default: {start_port})",
        )

        parser.add_argument(
            "--end",
            "-e",
            type=int,
            default=end_port,
            help=f"Ending Port (default: {end_port})",
        )

        parser.add_argument(
            "--delay",
            "-d",
            type=int,
            default=delay_ms,
            help=f"Delay between scans (default: {delay_ms})",
        )

        args = parser.parse_args()
        self.start_port: int = args.start
        self.end_port: int = args.end
        self.delay: int = args.delay
        self.target: str = args.target

    def __str__(self):
        return f"Target: {self.target}, Start Port: {self.start_port}, End Port: {self.end_port}, Delay: {self.delay}"

    def __repr__(self):
        return f"Target: {self.target}, Start Port: {self.start_port}, End Port: {self.end_port}, Delay: {self.delay}"
