pip install scapy

from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        # Determine the protocol
        if proto == 6:
            protocol = 'TCP'
        elif proto == 17:
            protocol = 'UDP'
        else:
            protocol = 'Other'

        # Get payload data
        payload = packet[IP].payload

        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {protocol}")
        print(f"Payload: {payload}")
        print("\n")

# Capture packets on the network interface (e.g., "eth0" or "wlan0")
# On Windows, you might use "Ethernet" or "Wi-Fi"
sniff(prn=packet_callback, filter="ip", iface="eth0", store=False)
