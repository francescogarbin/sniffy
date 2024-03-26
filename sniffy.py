import scapy.layers.inet
from scapy.all import *


def packet_callback(packet_):
    if packet.haslayer(scapy.layers.inet.IP) \
        and packet.haslayer(scapy.layers.inet.TCP) \
        and packet[scapy.layers.inet.TCP].dport == 5000 \
        and packet_[scapy.layers.inet.IP].dst == '192.168.255.247':
            print("packet:", packet_.summary())


sniff(filter="dst 192.168.255.247 and dst port 5000", prn=packet_callback, store=0)
