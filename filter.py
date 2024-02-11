from scapy.all import *
from scapy.layers.http import HTTPRequest
# Фильтрация HTTP-запросов
def process_packet(packet):
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        print("Запрашиваемый URL:", url)
# Сниффинг с применением функции фильтрации
sniff(iface="Ethernet", count=10, prn=process_packet, filter="port 80")