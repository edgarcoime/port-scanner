import sys
import time
from enum import Enum

from scapy.layers.inet import ICMP, IP, TCP
from scapy.sendrecv import conf, sr1

from argparser import Parser
from utils.constants import SCAN_RETRIES, SCAN_TIMEOUT_SEC


class PortStatus(Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    FILTERED = "FILTERED"
    UNKNOWN = "UNKNOWN"


class PortScanner:
    def __init__(self, args: Parser):
        self.config = args

    def scan(self):
        config = self.config
        print("Scanning Target: ", self.config.target)
        self.scan_port(config.target, 22)

    def scan_port(
        self, target: str, port: int, timeout=SCAN_TIMEOUT_SEC, retries=SCAN_RETRIES
    ) -> PortStatus:
        conf.verb = 0

        ip = IP(dst=target)
        tcp = TCP(dport=port, flags="S")

        return PortStatus.UNKNOWN

    def __str__(self) -> str:
        return f"config: {self.config}"

    def __repr__(self) -> str:
        return f"config: {self.config}"
