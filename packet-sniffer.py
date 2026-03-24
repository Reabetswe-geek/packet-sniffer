from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import argparse

parser =argparse.ArgumentParser(description="Packet Sniffer Tool")
parser.add_argument("--filter", help="BPF filter (tcp, udp, icmp, port 80)")
parser.add_argument("--ip", help="Flag specific IP as suspicious")
parser.add_argument("--count", type=int, help="Number of packet to capture")

args = parser.parse_args()

suspicious_ips = ["185.125.190.57"]
if args.ip: suspicious_ips.append(args.ip)

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
finally: print("[+] Exiting program")
