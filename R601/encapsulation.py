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
    ### Crée un paquet ICMP contenant des données UDP
    icmp_type = 8  # Echo Request
    icmp_code = 0
    checksum_value = 0
    identifier = random.randint(0, 65535)
    sequence_number = 1

    # L'en-tête ICMP sans checksum (qui sera calculé après)
    header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum_value, identifier, sequence_number)
    payload = udp_data

    # Calcul du checksum sur l'ensemble de l'en-tête + payload
    checksum_value = checksum(header + payload)

    # Re-crée l'en-tête avec le checksum correct
    header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum_value, identifier, sequence_number)

    return header + payload

### Test pour envoi d'ICMP
# def send_icmp_packet(dest_ip, udp_data):
#     ### Envoi du paquet ICMP
#     packet = create_icmp_packet(udp_data)

#     with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
#         s.sendto(packet, (dest_ip, 1))

### Test pour envoi d'UDP
def send_icmp_packet(dest_ip, udp_data):
    ### Envoi du paquet ICMP
    packet = create_icmp_packet(udp_data)

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.SOL_UDP) as s:
        s.sendto(udp_data, (dest_ip, 1))

### Avec demande user
# udp_payload = input("Quel message voulez-vous envoyer ?").encode()
# psource = int(input("Veuillez entrer un port source"))
# pdest = int(input("Veuillez entrer un port de destination"))
# ipdest = str(input("Veuillez entrer une IP de destination"))

### Sans demande
udp_payload = b'Salutations'
psource = 1234
pdest = 5678
ipdest = "172.21.1.44"
udp_packet = create_udp_packet(psource, pdest, udp_payload)
send_icmp_packet(ipdest, udp_packet)