import socket
import struct
import random
from time import time

def extract_udp_from_icmp(packet):
    ### Extrait le paquet UDP encapsulé dans un paquet ICMP
    icmp_header = packet[20:28]  # Le header ICMP commence à partir du byte 20
    udp_payload = packet[28:]    # Le payload commence après l'header ICMP

    ### Extraire le contenu UDP
    return udp_payload

def receive_icmp_packet():
    ### Réceptionne un paquet ICMP et désencapsule les données UDP
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        s.bind(('0.0.0.0', 0))  # Écoute sur toutes les interfaces
        while True:
            packet, addr = s.recvfrom(65535)
            udp_data = extract_udp_from_icmp(packet)
            print(f"Paquet UDP reçu de {addr}: {udp_data}")
