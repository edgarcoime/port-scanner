import sys
import time
from enum import Enum

from scapy.layers.inet import ICMP, IP, TCP
from scapy.sendrecv import conf, sr1

from argparser import Parser


class PortStatus(Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    FILTERED = "FILTERED"
    UNKNOWN = "UNKNOWN"


TIMEOUT_SEC = 2
RETRIES = 2


class PortScanner:
    def __init__(self, args: Parser):
        self.config = args

    def scan(self):
        config = self.config
        print("Scanning Target: ", self.config.target)
        self.scan_port(config.target, 22)

    def scan_port(
        self, target: str, port: int, timeout=TIMEOUT_SEC, retries=RETRIES
    ) -> PortStatus:
        conf.verb = 0

        ip = IP(dst=target)
        tcp = TCP(dport=port, flags="S")

        return PortStatus.UNKNOWN

    def __str__(self) -> str:
        return f"config: {self.config}"

    def __repr__(self) -> str:
        return f"config: {self.config}"
