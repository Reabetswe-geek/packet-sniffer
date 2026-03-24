from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

suspicious_ips = ["185.125.190.57"]

def process_packet(packet):
    if packet.haslayer(IP):
        ip = packet[IP]
        src = ip.src
        dst = ip.dst

        timestamp = datetime.now().strftime("H:%M:%S")

        log = f"[{timestamp}] {src} -> {dst}"

        if src in suspicious_ips or dst in suspicious_ips: log += " | ALERT: Suspicious IP"

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            log += f" | TCP Port: {tcp.dport}"

            if tcp.dport not in [80, 443]:
                log += " | ALERT: Unusual Port"

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            log += f" | UDP Port: {udp.dport}"

        elif packet.haslayer(ICMP):
            log += " | ICMP"

        print(log)

        with open("sniffer_log.txt" ,"a") as f: f.write(log + "\n")

print("=" * 50)
print("    Packet Sniffer Started (Press Ctrl+C to stop)")
print("=" * 50)

try: 
    sniff(prn=process_packet, store=False)
except KeyboardInterrupt:
     print("\n\n[!] Sniffer stopped  by user")
