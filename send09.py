import sys
from scapy.all import *
def packet_callback(packet):
    payload = packet[TCP].payload
    if isinstance(payload, bytes):
        payload = payload.decode(errors="ignore")
    print(f"[+] Payload: {payload}")

print("[*] Starting network sniffer. Press CTRL-C to stop.")
sniff(filter="tcp port 80 or tcp port 443", prn=packet_callback, store=0)