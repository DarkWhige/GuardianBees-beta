import socket

from scapy.all import sniff, IP, TCP, UDP

hostname_cache = {}

def display_name(ip_address):
    if ip_address not in hostname_cache:
        try:
            hostname_cache[ip_address] = socket.gethostbyaddr(ip_address)[0]
        except (socket.herror, socket.gaierror, TimeoutError):
            hostname_cache[ip_address] = ip_address

    return hostname_cache[ip_address]

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        print(f"{display_name(src_ip)} -> {display_name(dst_ip)} ({proto})")

sniff(prn=packet_callback, filter="ip", store=False)
