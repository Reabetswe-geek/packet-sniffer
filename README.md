# Python Packet Sniffer

#Overview

This project is a custom packet sniffer building python and Scapy.

##  Features
- Captures Live network packets
- Displays source and destination IPs
- Detects TCP, UDP, and ICMP protocols
- Flags unusual TCP ports
- Logs captured packets to file
- Detects unusual TCP ports
- Supports packet filtering

## Advanced Features (v2)
- Continious packet monitoring 
- Real time alerts for suspicious IPs
- Timestamped loggin
- Graceful shutdown (CTRL+C)

## Advanced Usage
- Run with filters:
python packet-sniffer.py -- filter tcp

- Detect suspicious IP:
Pythin packet-sniffer.py --ip

- Limited packet capture:
python packet-sniffer by --count 20

- combine options:
python-packet-sniffer.py --filter tcp --ip --count

# Tools Used
- Python
- Scapy
- Ubuntu (WSL)

## Skills Demonstrated
- Network packet analysis
- Python scripting
- Basic intrusion detection
