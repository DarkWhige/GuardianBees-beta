import os
import socket
from collections import defaultdict
from datetime import datetime

from scapy.all import IP, TCP, UDP, sniff

hostname_cache = {}


def display_name(ip_address):
    if ip_address not in hostname_cache:
        try:
            hostname_cache[ip_address] = socket.gethostbyaddr(ip_address)[0]
        except (socket.herror, socket.gaierror, TimeoutError):
            hostname_cache[ip_address] = ip_address

    return hostname_cache[ip_address]


def packet_callback(packet, requests):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if TCP in packet:
            request_type = "TCP"
            port = packet[TCP].dport
        elif UDP in packet:
            request_type = "UDP"
            port = packet[UDP].dport
        else:
            request_type = f"IP/{packet[IP].proto}"
            port = "-"

        requests[(request_type, src_ip, dst_ip, port)] += 1


def display_requests(requests):
    if not requests:
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] Network requests (last second):")
    for (request_type, src_ip, dst_ip, port), count in sorted(requests.items()):
        print(
            f"  {request_type}: {display_name(src_ip)} -> "
            f"{display_name(dst_ip)} | port={port} | requests={count}"
        )


def run_sniffer(interface=None):
    interface = interface or os.getenv("NETWORK_INTERFACE") or None
    requests = defaultdict(int)

    while True:
        try:
            sniff(
                iface=interface,
                prn=lambda packet: packet_callback(packet, requests),
                filter="ip",
                store=False,
                timeout=1,
            )
            display_requests(requests)
            requests.clear()
        except KeyboardInterrupt:
            display_requests(requests)
            print("Stopping network sniffer.")
            return
