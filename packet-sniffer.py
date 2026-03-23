from scapy.all import sniff, IP, TCP, UDP, ICMP

def process_packet(packet):
    if packet.haslayer(IP):
        ip = packet[IP]
        src = ip.src
        dst = ip.dst

        log = f"[+] {src} -> {dst}"

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            log += f" | TCP Port: {tcp.dport}"

            if tcp.dport not in [80, 443]:
                log += " | ALERT: Unusual Port"

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            log += f" | UDP Port: {udp.dport}"

        elif packet.haslayer(ICMP):
            log += " | ICMP Traffic"

        print(log)

        with open("sniffer_log.txt", "a") as file: file.write(log + "\n")

print("Starting packet sniffer with loggin...\n")

sniff(prn=process_packet, count=30)
