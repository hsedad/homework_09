import sys
from scapy.all import *
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.inet import IP, TCP
load_layer("http")
req = HTTP()/HTTPRequest(
    Accept_Encoding=b'gzip, deflate',
    Cache_Control=b'no-cache',
    Connection=b'keep-alive',
    Host=b'www.secdev.org',
    Pragma=b'no-cache'
)
a = TCP_client.tcplink(HTTP, "192.168.1.11", 80)
answer = a.sr1(req)
print(a.sr1)
a.close()
with open("result.html", "wb") as file:
    file.write(answer.load)