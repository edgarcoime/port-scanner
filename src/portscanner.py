import sys
import time

from scapy.all import IP, TCP, conf, sr1

from argparser import Parser


class PortScanner:
    def __init__(self, args: Parser):
        self.config = args

    def scan(self):
        config = self.config
        print("Scanning Target: ", self.config.target)

    def __str__(self) -> str:
        return f"config: {self.config}"

    def __repr__(self) -> str:
        return f"config: {self.config}"
