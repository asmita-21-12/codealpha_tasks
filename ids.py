from scapy.all import *
from collections import Counter
import time

# Define thresholds and monitoring time window
SYN_THRESHOLD = 100  # Threshold for SYN packets (potential SYN flood)
DNS_QUERY_THRESHOLD = 50  # Threshold for unusual DNS activity
TIME_WINDOW = 10  # Time window in seconds

# Data storage for packet statistics
packet_stats = {
    "syn_packets": Counter(),
    "dns_queries": Counter(),
    "port_scans": set(),
}

def monitor_packet(packet):
    # Track suspicious SYN packets (possible SYN flood)
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        src_ip = packet[IP].src
        packet_stats["syn_packets"][src_ip] += 1
        if packet_stats["syn_packets"][src_ip] > SYN_THRESHOLD:
            print(f"[ALERT] Potential SYN flood detected from {src_ip}")

    # Track DNS queries
    if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS query
        src_ip = packet[IP].src
        packet_stats["dns_queries"][src_ip] += 1
        if packet_stats["dns_queries"][src_ip] > DNS_QUERY_THRESHOLD:
            print(f"[ALERT] Unusual DNS activity from {src_ip}")

    # Detect port scans
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        src_ip = packet[IP].src
        dst_port = packet[IP].dport
        packet_stats["port_scans"].add((src_ip, dst_port))
        if len({dst_port for (ip, dst_port) in packet_stats["port_scans"] if ip == src_ip}) > 10:
            print(f"[ALERT] Port scan detected from {src_ip}")

def reset_stats():
    """Reset statistics to avoid stale data."""
    packet_stats["syn_packets"].clear()
    packet_stats["dns_queries"].clear()
    packet_stats["port_scans"].clear()

def main():
    print("Starting Intrusion Detection System...")
    start_time = time.time()

    while True:
        # Capture packets in real time
        sniff(prn=monitor_packet, timeout=TIME_WINDOW, store=False)

        # Reset statistics periodically
        if time.time() - start_time > TIME_WINDOW:
            reset_stats()
            start_time = time.time()

if __name__ == "__main__":
    main()
