import os
import socket
import time

from scapy.all import DNS, IP, TCP, UDP, get_if_addr, get_if_list, sniff


def _local_addresses():
    addresses = {"127.0.0.1"}
    try:
        addresses.update(
            get_if_addr(interface)
            for interface in get_if_list()
            if get_if_addr(interface) not in {"0.0.0.0", "127.0.0.1"}
        )
    except OSError:
        pass

    try:
        addresses.add(socket.gethostbyname(socket.gethostname()))
    except socket.gaierror:
        pass
    return addresses


def packet_to_record(packet):
    """Convert a captured Scapy packet into the aggregator input schema."""
    if IP not in packet:
        return None

    record = {
        "ts": time.time(),
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "proto": f"IP/{packet[IP].proto}",
        "sport": None,
        "dport": None,
        "tcp_syn": False,
        "direction": "sortant" if packet[IP].src in _local_addresses() else "local",
        "dns_query": None,
        "size": len(packet),
    }

    if TCP in packet:
        record["proto"] = "TCP"
        record["sport"] = packet[TCP].sport
        record["dport"] = packet[TCP].dport
        record["tcp_syn"] = bool(packet[TCP].flags & 0x02)
    elif UDP in packet:
        record["proto"] = "UDP"
        record["sport"] = packet[UDP].sport
        record["dport"] = packet[UDP].dport

    if DNS in packet and packet[DNS].qr == 0 and packet[DNS].qd:
        query_name = packet[DNS].qd.qname
        if isinstance(query_name, bytes):
            query_name = query_name.rstrip(b".").decode("utf-8", errors="replace")
        record["dns_query"] = str(query_name).rstrip(".")

    return record


def run_sniffer(interface=None, on_window=None, window_seconds=30):
    """Capture packets and pass each time window to ``on_window``."""
    interface = interface or os.getenv("NETWORK_INTERFACE") or None
    on_window = on_window or _print_window

    def collect(packet, records):
        record = packet_to_record(packet)
        if record is not None:
            records.append(record)

    records = []
    while True:
        try:
            sniff(
                iface=interface,
                prn=lambda packet: collect(packet, records),
                filter="ip",
                store=False,
                timeout=window_seconds,
            )
            window_records = records[:]
            records.clear()
            on_window(window_records)
        except KeyboardInterrupt:
            if records:
                on_window(records)
            print("Stopping network sniffer.")
            return


def _print_window(records):
    for record in records:
        print(record)
