import socket
import struct
import random
from time import time

def capture_wireguard_udp_packet(port=51820):
    ### Capture une trame UDP spécifique à WireGuard envoyée depuis la même machine
    # Créer un socket raw pour capturer les paquets UDP
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP) as s:
        s.bind(('0.0.0.0', 0))  # Bind sur toutes les interfaces et ports
        while True:
            # Capturer un paquet
            packet, addr = s.recvfrom(65535)
            
            # Vérifier si le paquet est un paquet UDP et correspond au port de WireGuard
            ip_header = packet[:20]  # L'en-tête IP est généralement de 20 octets
            udp_header = packet[20:28]  # L'en-tête UDP est généralement de 8 octets
            
            # Extraire les informations de port source et destination du paquet UDP
            src_port, dest_port = struct.unpack('!HH', udp_header[:4])

            if dest_port == port:
                print(f"Paquet UDP WireGuard capturé de {addr}:")
                print(packet)
                return packet  # Retourner le paquet UDP capturé
            
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
def send_icmp_packet(dest_ip, udp_data):
    ### Envoi du paquet ICMP
    packet = create_icmp_packet(udp_data)

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        s.sendto(packet, (dest_ip, 1))

### Test pour envoi d'UDP
def send_udp_packet(dest_ip, udp_data):
    ### Envoi du paquet UDP
    packet = create_icmp_packet(udp_data)

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.SOL_UDP) as s:
        s.sendto(udp_data, (dest_ip, 1))

### MAIN ###
if __name__ == "__main__":
    ipdest = input("Entrez l'IP de destination : ").strip()
    wg_payload = capture_wireguard_udp_packet()
    print("[*] Démarrage de l'envoi en continu...")
    while True:
        send_icmp_packet(ipdest, wg_payload)
        time.sleep(1)  # Ajuste selon besoin (1 seconde entre les paquets ici)


## Avec demande user
# udp_payload = input("Quel message voulez-vous envoyer ?").encode()
# psource = int(input("Veuillez entrer un port source"))
# pdest = int(input("Veuillez entrer un port de destination"))
# ipdest = str(input("Veuillez entrer une IP de destination"))

### Sans demande
# udp_payload = b'Salutations'
# psource = 1234
# pdest = 5678
# ipdest = "172.21.1.44"
# udp_packet = create_udp_packet(psource, pdest, udp_payload)

### Avec capture Wireguard
# ipdest = "172.21.1.44"
# udp_packet = capture_wireguard_udp_packet()

### Envoi UDP
# send_udp_packet(ipdest, udp_packet)

### Envoi ICMP
# send_icmp_packet(ipdest, udp_packet)

### TEST FULL SCRIPT ###
# a = int(input("Voulez-vous créer un paquet fictif pour tester (1) ou bien capter un paquet Wireguard (2) ? "))

# if a == 1:
#     b = int(input("Voulez-vous utiliser les champs préremplis ? (Oui = 1 / Non = 2) "))
#     if b == 1:
#         udp_payload = b'Salutations'
#         psource = 1234
#         pdest = 5678
#         ipdest = "172.21.1.44"
#         udp_packet = create_udp_packet(psource, pdest, udp_payload)
#         c = int(input("Voulez-vous l'envoyer en UDP (1) ou en ICMP (2) ? "))
#         if c == 1:
#             print(f'envoi du paquet')
#             send_udp_packet(ipdest, udp_packet)
#         elif c == 2:
#             send_icmp_packet(ipdest, udp_packet)
#     elif b == 2:
#         udp_payload = input("Quel message voulez-vous envoyer ?").encode()
#         psource = int(input("Veuillez entrer un port source: "))
#         pdest = int(input("Veuillez entrer un port de destination: "))
#         ipdest = str(input("Veuillez entrer une IP de destination: "))
#         udp_packet = create_udp_packet(psource, pdest, udp_payload)
#         c = int(input("Voulez-vous l'envoyer en UDP (1) ou en ICMP (2) ? "))
#         if c == 1:
#             send_udp_packet(ipdest, udp_packet)
#         elif c == 2:
#             send_icmp_packet(ipdest, udp_packet)

# elif a == 2:
#     ipdest = str(input("Veuillez entrer l'IP de destination du paquet : "))
#     udp_packet = capture_wireguard_udp_packet()  # Assurez-vous que cette fonction renvoie un paquet valide
#     if udp_packet is not None:
#         c = int(input("Voulez-vous l'envoyer en UDP (1) ou en ICMP (2) ? "))
#         if c == 1:
#             send_udp_packet(ipdest, udp_packet)
#         elif c == 2:
#             send_icmp_packet(ipdest, udp_packet)
#     else:
#         print("Aucun paquet capturé.")