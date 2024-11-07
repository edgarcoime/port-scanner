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
        print("Scanning Target IP: ", self.config.target)

        ports = [22, 8721, 3000]

        for p in ports:
            status = self.scan_port(config.target, p)
            print(status)

    def scan_port(
        self, target: str, port: int, timeout=SCAN_TIMEOUT_SEC, retries=SCAN_RETRIES
    ) -> PortStatus:
        conf.verb = 0

        # Create SYN packet
        ip = IP(dst=target)
        tcp = TCP(dport=port, flags="S")
        packet = ip / tcp

        print(f"Scanning {target}:{port}")

        # Send SYN packet until retries are exhausted
        for _ in range(retries):
            res = sr1(packet, timeout=timeout)
            if res is None:
                return PortStatus.FILTERED

            # Check if the response has the SYN-ACK flag set
            if res.haslayer(TCP):
                tcp_layer = res.getlayer(TCP)
                if tcp_layer and tcp_layer.flags == "SA":
                    return PortStatus.OPEN
                if tcp_layer and "R" in tcp_layer.flags:
                    return PortStatus.CLOSED

            # check for icmp error
            elif res.haslayer(ICMP):
                icmp_layer = res.getlayer(ICMP)
                if (
                    icmp_layer
                    and icmp_layer.type == 3
                    and icmp_layer.code in [1, 2, 3, 9, 10, 13]
                ):
                    return PortStatus.FILTERED

        return PortStatus.UNKNOWN

    def __str__(self) -> str:
        return f"config: {self.config}"

    def __repr__(self) -> str:
        return f"config: {self.config}"
