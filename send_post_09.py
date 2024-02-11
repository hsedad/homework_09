#!/usr/bin/env python
import sys
from scapy.all import *
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.inet import IP, TCP
dst_ip = "192.168.1.11"
dst_port = 80

post_data = "key1=user&key2=user"

ip = IP(dst=dst_ip)
tcp = TCP(dport=dst_port)
http = HTTP() / HTTPRequest(
    Method="POST",
    Host=dst_ip,
    Path="/post-endpoint",
    Content_Length=str(len(post_data)),
    Accept_Encoding="gzip, deflate",
    Content_Type="application/x-www-form-urlencoded"
) / post_data

# send(ip / tcp / http)

response = srp1(ip / tcp / http, timeout=5, iface='eth0')
if response:
    http_response = response[HTTPResponse]
    print(http_response.Statuse_Line)
    print(http_response.load)
else:
    print("No Response")