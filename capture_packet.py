
import subprocess
import signal
import sys
import time
import shutil
import pyshark
import os
import json
import importlib



# Configuration
TSHARK_PATH = r'C:\Users\Karan\Wireshark\tshark.exe'
os.environ['TSHARK_PATH'] = TSHARK_PATH
CAPTURE_FILE = 'capture.pcap'
OUTPUT_DIR = r'C:\Users\Karan\Desktop\SOU\\5.SEM\0_final_packet_capture'  # Change this to your desired output directory
DURATION = 30  # Duration in seconds for capturing
PACKET_LIMIT = 50  # Limit the number of packets
TIMEOUT = 60  # Timeout duration in seconds
EXTERNAL_IP = "192.168.1.100"  # Replace with the actual external IP you want to monitor
PORT_SCAN_THRESHOLD = 5  # Number of SYN packets to different ports within a short period to flag as suspicious
NON_STANDARD_PORTS = [i for i in range(49152, 65535)]  # Non-standard ports (dynamic/private ports)
VPN_PORT = 1194  # Port used for VPN (e.g., OpenVPN)

# Trusted User-Agents
TRUSTED_USER_AGENTS = [
    'Mozilla/5.0',
    'Chrome/91.0',
    'Safari/537.36'
]

# Predefined list of network interfaces
INTERFACES = {
    1: "VMware Network Adapter VMnet1",
    2: "Ethernet 2",
    3: "Local Area Connection* 2",
    4: "Wi-Fi 3",
    5: "wifi",
    6: "Adapter for loopback traffic capture",
    7: "Ethernet"
}

# Protocol Database (JSON example)
PROTOCOL_DATABASE = {
    "http": {
        "port": 80,
        "dissector": "http_dissector.py",
        "description": "Handles HTTP protocol"
    },
    "ftp": {
        "port": 21,
        "dissector": "ftp_dissector.py",
        "description": "Handles FTP protocol"
    }
    # Add more protocols as needed
}

def choose_interface():
    print("Choose an interface from the following list:")
    for num, interface in INTERFACES.items():
        print(f"{num}: {interface}")
    choice = int(input("Enter the number corresponding to the interface: "))
    selected_interface = INTERFACES.get(choice, None)
    if selected_interface:
        print(f"Selected interface: {selected_interface}")
    return selected_interface

def start_capture(interface, output_file):
    cmd = [TSHARK_PATH, '-i', interface, '-w', output_file]
    print(f"Starting capture on interface '{interface}' and saving to '{output_file}'...")
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Start capturing with PyShark
    capture = pyshark.LiveCapture(interface=interface, tshark_path=TSHARK_PATH)
    capture.set_debug()  # Enable debug mode

    outbound_traffic_counter = 0
    port_scan_tracker = {}
    icmp_counter = 0
    dns_queries = {}
    suspicious_ports = set()
    suspicious_user_agents = set()
    protocol_counts = {}  # Dictionary to count packets by protocol

    def real_time_packet_display(packet):
        nonlocal outbound_traffic_counter
        nonlocal port_scan_tracker
        nonlocal icmp_counter
        nonlocal dns_queries
        nonlocal suspicious_ports
        nonlocal suspicious_user_agents

        protocol = packet.highest_layer
        
        # Update protocol count
        if protocol not in protocol_counts:
            protocol_counts[protocol] = 0
        protocol_counts[protocol] += 1
        
        # Display packet details
        time = packet.sniff_time
        source = packet.ip.src if 'IP' in packet else 'N/A'
        destination = packet.ip.dst if 'IP' in packet else 'N/A'
        length = packet.length
        info = "N/A"

        
        
        # Extract info based on protocol
        if 'HTTP' in packet:
            info = f"HTTP {packet.http.request_method} {packet.http.host}{packet.http.request_uri}"
            user_agent = packet.http.user_agent if 'http.user_agent' in packet.http.field_names else 'N/A'
            if not any(known_ua in user_agent for known_ua in TRUSTED_USER_AGENTS):
                suspicious_user_agents.add(user_agent)
                print(f"Suspicious HTTP User-Agent detected: {user_agent}")
        elif 'TCP' in packet:
            info = f"TCP {packet.tcp.srcport} -> {packet.tcp.dstport} Seq={packet.tcp.seq} Ack={packet.tcp.ack}"
            if 'IP' in packet and packet.ip.dst == EXTERNAL_IP:
                outbound_traffic_counter += 1
            if 'tcp.flags.syn' in packet and packet.tcp.flags.syn == '1' and packet.tcp.flags.ack == '0':
                if source not in port_scan_tracker:
                    port_scan_tracker[source] = []
                port_scan_tracker[source].append(packet.tcp.dstport)
                if len(set(port_scan_tracker[source])) >= PORT_SCAN_THRESHOLD:
                    print(f"Port scanning activity detected from IP: {source}. Scanned ports: {port_scan_tracker[source]}")
            if int(packet.tcp.dstport) in NON_STANDARD_PORTS:
                suspicious_ports.add(packet.tcp.dstport)
                print(f"Suspicious use of non-standard port detected: {packet.tcp.dstport}")
        elif 'UDP' in packet:
            info = f"UDP {packet.udp.srcport} -> {packet.udp.dstport}"
            if packet.udp.dstport == VPN_PORT:
                print(f"Potential VPN or remote access activity detected on port {VPN_PORT}")
        elif 'DNS' in packet:
            info = f"DNS Query: {packet.dns.qry_name}"
            if packet.dns.qry_name not in dns_queries:
                dns_queries[packet.dns.qry_name] = 0
            dns_queries[packet.dns.qry_name] += 1
            if dns_queries[packet.dns.qry_name] > 10:  # Replace with actual threshold
                print(f"Unusual DNS request detected: {packet.dns.qry_name}")
        elif 'ICMP' in packet:
            info = f"ICMP Type={packet.icmp.type} Code={packet.icmp.code}"
            icmp_counter += 1
            if icmp_counter > 50:  # Replace with actual threshold
                print(f"Excessive ICMP traffic detected.")
        elif 'ARP' in packet:
            info = f"ARP {packet.arp.src_proto_ipv4} is at {packet.arp.src_hw_mac}"

        print(f"Time: {time}, Source: {source}, Destination: {destination}, Protocol: {protocol}, Length: {length}, Info: {info}")

        # Check for abnormal outbound traffic volume
        if outbound_traffic_counter > 10:  # Example threshold
            print(f"High volume of outbound traffic detected to IP {EXTERNAL_IP}.")

    try:
        # Start real-time packet capture and display
        capture.apply_on_packets(real_time_packet_display, timeout=DURATION)
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        stop_capture(process)
    return process, protocol_counts

def stop_capture(process):
    process.terminate()
    process.wait()  # Ensure the process has terminated
    print("Capture stopped.")

def extract_packet_details(packet):
    """
    Extracts detailed information from a packet.

    Parameters:
        packet (pyshark.packet.packet.Packet): The packet to extract details from.

    Returns:
        dict: A dictionary containing detailed packet information.
    """
    return {
        "Frame Number": packet.frame_info.number if 'frame_info' in packet else 'N/A',
        "Arrival Time": packet.sniff_time.isoformat(),
        "Frame Length": packet.length,
        "Protocols in Frame": packet.highest_layer,
        "Source IP Address": packet.ip.src if 'IP' in packet else 'N/A',
        "Destination IP Address": packet.ip.dst if 'IP' in packet else 'N/A',
        "Protocol": packet.ip.proto if 'IP' in packet else 'N/A',
        "TTL": packet.ip.ttl if 'IP' in packet else 'N/A',
        "Header Checksum": packet.ip.checksum if 'IP' in packet else 'N/A',
        "Source MAC Address": packet.eth.src if 'eth' in packet else 'N/A',
        "Destination MAC Address": packet.eth.dst if 'eth' in packet else 'N/A',
        "EtherType": packet.eth.type if 'eth' in packet else 'N/A',
        "Source Port": packet.tcp.srcport if 'TCP' in packet else (packet.udp.srcport if 'UDP' in packet else 'N/A'),
        "Destination Port": packet.tcp.dstport if 'TCP' in packet else (packet.udp.dstport if 'UDP' in packet else 'N/A'),
        "Sequence Number": packet.tcp.seq if 'TCP' in packet else 'N/A',
        "Acknowledgment Number": packet.tcp.ack if 'TCP' in packet else 'N/A',
        "Flags": packet.tcp.flags if 'TCP' in packet else 'N/A',
        "Window Size": packet.tcp.window_size if 'TCP' in packet else 'N/A',
        "Checksum": packet.tcp.checksum if 'TCP' in packet else 'N/A',
        "Protocol-Specific Details": "",  # Placeholder for further protocol-specific details
    }


def move_pcap_file(file_path, destination_dir):
    time.sleep(5)  # Wait a bit to ensure tshark has finished using the file
    destination_file = os.path.join(destination_dir, CAPTURE_FILE)
    try:
        shutil.move(file_path, destination_file)
        print(f"File moved to {destination_file}")
    except Exception as e:
        print(f"Error moving file: {e}")

def analyze_pcap(file_path):
    capture = pyshark.FileCapture(file_path, tshark_path=TSHARK_PATH)
    capture.set_debug()

    print("\nPacket Analysis:\n")
    packet_count = 0
    packet_data = []
    outbound_traffic_counter = 0
    port_scan_tracker = {}
    icmp_counter = 0
    dns_queries = {}
    suspicious_ports = set()
    suspicious_user_agents = set()
    protocol_counts = {}  # Dictionary to count packets by protocol

    for packet in capture:
        if packet_count >= PACKET_LIMIT:
            break
        protocol = packet.highest_layer

        # Update protocol count
        if protocol not in protocol_counts:
            protocol_counts[protocol] = 0
        protocol_counts[protocol] += 1
        
        # Extracting necessary fields from the packet
        time = packet.sniff_time.isoformat()
        source = packet.ip.src if hasattr(packet, 'ip') else 'N/A'
        destination = packet.ip.dst if hasattr(packet, 'ip') else 'N/A'
        protocol = packet.transport_layer if hasattr(packet, 'transport_layer') else 'N/A'
        length = packet.length if hasattr(packet, 'length') else 'N/A'
        
        # Attempting to extract 'info' and setting a default value if not found
        info = getattr(packet, 'info', 'No Info Available')


        # Extract info based on protocol
        if 'HTTP' in packet:
            info = f"HTTP {packet.http.request_method} {packet.http.host}{packet.http.request_uri}"
            user_agent = packet.http.user_agent if 'http.user_agent' in packet.http.field_names else 'N/A'
            if not any(known_ua in user_agent for known_ua in TRUSTED_USER_AGENTS):
                suspicious_user_agents.add(user_agent)
        elif 'TCP' in packet:
            info = f"TCP {packet.tcp.srcport} -> {packet.tcp.dstport} Seq={packet.tcp.seq} Ack={packet.tcp.ack}"
            if 'IP' in packet and packet.ip.dst == EXTERNAL_IP:
                outbound_traffic_counter += 1
            if 'tcp.flags.syn' in packet and packet.tcp.flags.syn == '1' and packet.tcp.flags.ack == '0':
                if source not in port_scan_tracker:
                    port_scan_tracker[source] = []
                port_scan_tracker[source].append(packet.tcp.dstport)
                if len(set(port_scan_tracker[source])) >= PORT_SCAN_THRESHOLD:
                    print(f"Port scanning activity detected from IP: {source}. Scanned ports: {port_scan_tracker[source]}")
            if int(packet.tcp.dstport) in NON_STANDARD_PORTS:
                suspicious_ports.add(packet.tcp.dstport)
                print(f"Suspicious use of non-standard port detected: {packet.tcp.dstport}")
        elif 'UDP' in packet:
            info = f"UDP {packet.udp.srcport} -> {packet.udp.dstport}"
            if packet.udp.dstport == VPN_PORT:
                print(f"Potential VPN or remote access activity detected on port {VPN_PORT}")
        elif 'DNS' in packet:
            info = f"DNS Query: {packet.dns.qry_name}"
            if packet.dns.qry_name not in dns_queries:
                dns_queries[packet.dns.qry_name] = 0
            dns_queries[packet.dns.qry_name] += 1
            if dns_queries[packet.dns.qry_name] > 10:  # Replace with actual threshold
                print(f"Unusual DNS request detected: {packet.dns.qry_name}")
        elif 'ICMP' in packet:
            info = f"ICMP Type={packet.icmp.type} Code={packet.icmp.code}"
            icmp_counter += 1
            if icmp_counter > 50:  # Replace with actual threshold
                print(f"Excessive ICMP traffic detected.")
        elif 'ARP' in packet:
            info = f"ARP {packet.arp.src_proto_ipv4} is at {packet.arp.src_hw_mac}"

        print(f"Time: {time}, Source: {source}, Destination: {destination}, Protocol: {protocol}, Length: {length}, Info: {info}")
        packet_data.append({
            "time": time,
            "source": source,
            "destination": destination,
            "protocol": protocol,
            "length": length,
            "info": info
        })

        packet_details = extract_packet_details(packet)
        packet_data.append(packet_details)
        packet_count += 1

    # Create summary statistics
    summary = {
        "Total Packets Captured": packet_count,
        "Outbound Traffic Count": outbound_traffic_counter,
        "Suspicious Ports Detected": list(suspicious_ports),
        "Suspicious User Agents Detected": list(suspicious_user_agents),
        "ICMP Traffic Count": icmp_counter,
        "DNS Queries Detected": len(dns_queries),
        "Protocol Counts": protocol_counts,
        "Packet Details": packet_data
    }

    # Write summary to JSON file
    summary_file = file_path.replace('.pcap', '_summary.json')
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=4)
    print(f"Summary saved to {summary_file}")

def main():
    # Choose the interface
    interface = choose_interface()
    if not interface:
        print("Invalid interface selection.")
        return

    # Start packet capture
    process, protocol_counts = start_capture(interface, CAPTURE_FILE)

    # Wait for the duration of the capture
    print(f"Capturing for {DURATION} seconds...")
    time.sleep(DURATION + 10)  # Added buffer time

    # Stop packet capture
    stop_capture(process)

    # Move pcap file
    move_pcap_file(CAPTURE_FILE, OUTPUT_DIR)

    # Analyze pcap file
    analyze_pcap(os.path.join(OUTPUT_DIR, CAPTURE_FILE))

if __name__ == "__main__":
    # Handle Ctrl+C to terminate the script gracefully
    def signal_handler(sig, frame):
        print("\nTerminating the script...")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    main()













