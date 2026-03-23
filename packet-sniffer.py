from scapy.all import sniff, IP, TCP, UDP, ICMP

def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"\n[+] IP Packet: {ip_layer.src} -> {ip_layer.dst}")

        if packet.haslayer(TCP):
            print("[+] Protocol: TCP")

        elif packet.haslayer(UDP):
            print("[+] Protocol: UDP")

        elif packet.haslayer(ICMP):
            print("[+] Protocol: ICMP")

print("Starting advanced packet sniffer...")

sniff(prn=process_packet, count=20)
