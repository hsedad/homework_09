import sys
from scapy.all import *
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.inet import  IP, TCP
load_layer("http")
http_request("192.168.1.11", "/", display=True)