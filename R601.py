#!/usr/bin/env python3

from scapy.all import *

# Interface réseau à adapter
iface_sniff = "eth0"
iface_send = iface_sniff

# Filtre pour capturer un ICMP contenant un UDP en payload
print("[+] Sniffing d'un paquet ICMP contenant UDP...")
captured_packets = sniff(filter="icmp", count=1, timeout=10, iface=iface_sniff)

if not captured_packets:
    print("[-] Aucun paquet ICMP capturé.")
    exit(1)

# Affichage du paquet capturé
original_packet = captured_packets[0]
print("[+] Paquet ICMP capturé :")
original_packet.show()

# Vérification que le paquet contient bien UDP encapsulé
if not original_packet.haslayer(ICMP) or not original_packet.haslayer(UDP):
    print("[-] Le paquet capturé ne contient pas de segment UDP.")
    exit(1)

# Extraction des champs importants
src_ip = original_packet[IP].src
dst_ip = original_packet[IP].dst
udp_payload = original_packet[UDP].payload.load if original_packet[UDP].payload else b"Test UDP"

# Construction d'un nouveau paquet basé sur celui sniffé
new_icmp_packet = (
    IP(src=src_ip, dst=dst_ip) /
    ICMP(type=8) /  # Echo Request
    UDP(sport=original_packet[UDP].sport, dport=original_packet[UDP].dport) /
    Raw(load=udp_payload)
)

# Encapsulation Ethernet
new_ethernet_frame = Ether(dst="ff:ff:ff:ff:ff:ff") / new_icmp_packet

print("[+] Envoi du paquet forgé...")
sendp(new_ethernet_frame, iface=iface_send, verbose=True)
