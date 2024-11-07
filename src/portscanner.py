import datetime
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum
from time import sleep

from scapy.config import conf
from scapy.layers.inet import ICMP, IP, TCP
from scapy.sendrecv import sr1

from argparser import Parser
from utils.constants import SCAN_RETRIES, SCAN_TIMEOUT_SEC

# Create logs/errors directory if it doesn't exist
os.makedirs("logs/", exist_ok=True)

# Set up logging configuration
logging.basicConfig(
    filename="logs/error.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.ERROR,
)


class PortStatus(Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    FILTERED = "FILTERED"
    UNKNOWN = "UNKNOWN"


class PortScanner:
    def __init__(self, args: Parser):
        conf.verb = False
        self.config = args

    def check_target(self):
        ip = IP(dst=self.config.target)
        icmp = ICMP()
        res = sr1(ip / icmp, timeout=SCAN_TIMEOUT_SEC)
        if res and res.haslayer(ICMP):
            icmp_layer = res.getlayer(ICMP)
            if icmp_layer and icmp_layer.type == 0 and icmp_layer.code == 0:
                return
        sys.exit(f"Target {self.config.target} is not reachable.")

    def scan(self):
        self.check_target()
        config = self.config
        print("Scanning Target IP: ", self.config.target)

        rst_packet = IP(dst=config.target) / TCP(dport=config.end_port, flags="R")
        open_ports = []
        filtered_ports = []
        closed_ports = 0
        unknown_ports = 0
        scanned_ports = 0
        start_time = datetime.datetime.now()

        with ThreadPoolExecutor(max_workers=config.max_threads) as executor:
            # create threads
            futures = {}
            for p in range(config.start_port, config.end_port + 1):
                futures[executor.submit(self.scan_port, config.target, p)] = p
                sleep(config.delay)

            # wait for threads to complete
            for future in as_completed(futures):
                port = futures[future]
                try:
                    scanned_ports += 1
                    if scanned_ports % 100 == 0:
                        print(
                            f"Scanned {scanned_ports}/{config.end_port - config.start_port + 1} ports"
                        )

                    status = future.result()
                    if status == PortStatus.OPEN:
                        open_ports.append(port)
                        sr1(rst_packet, timeout=1)
                    elif status == PortStatus.FILTERED:
                        filtered_ports.append(port)
                        sr1(rst_packet, timeout=1)
                    elif status == PortStatus.CLOSED:
                        closed_ports += 1
                    else:
                        unknown_ports += 1

                except Exception as e:
                    # output the error into an error log file
                    msg = f"Port {port}: Error - {e}"
                    logging.error(msg)
                    print(msg, flush=True)

        end_time = datetime.datetime.now()
        elapsed_time = (end_time - start_time).total_seconds()

        print(
            "\nScanned a total of {}/{} ports in {} seconds".format(
                scanned_ports,
                config.end_port - config.start_port + 1,
                round(elapsed_time, 4),
            )
        )
        print(f"Open ports: {len(open_ports)}")
        print(f"Filtered ports: {len(filtered_ports)}")
        print(f"Closed ports: {closed_ports}\n")

        if len(open_ports) > 0:
            print("Found the following OPEN ports: ")
            for p in open_ports:
                print(f"  - {p}")

        # if len(filtered_ports) > 0:
        #     print("Found the following FILTERED ports: ")
        #     for p in filtered_ports:
        #         print(f"  - {p}")

    def scan_port(
        self, target: str, port: int, timeout=SCAN_TIMEOUT_SEC, retries=SCAN_RETRIES
    ) -> PortStatus:

        # Create SYN packet
        ip = IP(dst=target)
        tcp = TCP(dport=port, flags="S")
        packet = ip / tcp

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
        return f"PortScanner: \n{self.config}"

    def __repr__(self) -> str:
        return self.__str__()
