import socket
import struct
import random
from time import time

def create_udp_packet(source_port, dest_port, data):
    """Crée un paquet UDP binaire avec le port source, le port destination et le payload"""
    udp_length = 8 + len(data)  # 8 octets d'en-tête + taille du payload
    udp_checksum = 0  # Pour les tests, on met à 0

    # Création du header UDP
    udp_header = struct.pack('!HHHH', source_port, dest_port, udp_length, udp_checksum)

    # Retourne le paquet UDP complet
    return udp_header + data

def checksum(msg):
    ### Retour du checksum pour le message en entrée
    s = 0
    for i in range (0, len(msg), 2):
        w = (msg[i] << 8) + (msg[i+1] if i+1 < len(msg) else 0)
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += (s >>16)
    return ~s & 0xffff

def create_icmp_packet(udp_data):
    ### Création du paquet ICMP avec les données  UDP dedans
    icmp_type = 8
    icmp_code = 0
    checksum_value = 0
    identifier = random.randint(0,65535)
    sequence_number = 1

    ### Création du header
    header = struct.pack('bbHHh', icmp_type, icmp_code, checksum_value, identifier, sequence_number)
    payload = udp_data

    ### Calcul du checksum ICMP
    checksum_value = checksum(header + payload)
    header = struct.pack('bbHHh', icmp_type, icmp_code, checksum_value, identifier, sequence_number)

    return header + payload

def send_icmp_packet(dest_ip, udp_data):
    ### Envoi du paquet ICMP
    packet = create_icmp_packet(udp_data)

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        s.sendto(packet, (dest_ip, 1))

udp_payload = b'Hello'
udp_packet = create_udp_packet(1234, 5678, udp_payload)
send_icmp_packet("172.21.1.118", udp_packet)