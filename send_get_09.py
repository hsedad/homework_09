#!/usr/bin/env python
import sys
from scapy.all import *
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.inet import  IP, TCP
dst_ip = "192.168.1.11"
dst_port = 80

ip = IP(dst=dst_ip)
tcp = TCP(dport=dst_port)
http = HTTP() / HTTPRequest(Method="GET", Host=dst_ip, Path="/")

# send(ip / tcp / http)

response = sr1(ip / tcp / http, timeout=5)

if response:
    http_response = response[HTTPResponse]
    print(http_response.Statuse_Line)
    print(http_response.load)
else:
    print("No Response")