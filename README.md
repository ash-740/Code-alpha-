# Code-alpha-
Cyber Security Task List

from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        # Protocol decoding
        if proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        elif proto == 1:
            protocol = "ICMP"
        else:
            protocol = str(proto)

        print(f"\n[+] Packet Captured:")
        print(f"    From: {src_ip} --> To: {dst_ip}")
        print(f"    Protocol: {protocol}")

        # Display payload if any
        if packet.payload:
            print(f"    Payload: {bytes(packet.payload)[-20:]}")  # Print last 20 bytes

# Start sniffing (stop with Ctrl+C)
print("Sniffing packets... Press Ctrl+C to stop.\n")
sniff(prn=packet_callback, store=False)