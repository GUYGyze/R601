import socket
import struct
import random
from time import time

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