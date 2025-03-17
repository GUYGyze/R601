import socket
import struct

def extract_udp_from_icmp(packet):
    """Extrait le paquet UDP encapsulé dans le paquet ICMP"""
    # On suppose que le paquet ICMP est bien formé et que l'en-tête IP est de taille standard (20 octets)
    icmp_header = packet[20:28]  # Extraire l'en-tête ICMP (partie après l'en-tête IP)
    udp_payload = packet[28:]    # Le reste du paquet après l'en-tête ICMP est le payload UDP

    # Retourner le payload UDP
    return udp_payload

def receive_icmp_packet():
    """Réceptionne un paquet ICMP et extrait les données UDP encapsulées"""
    # Créer un socket raw pour écouter les paquets ICMP entrants
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        s.bind(('0.0.0.0', 0))  # Écoute sur toutes les interfaces
        while True:
            # Réception d'un paquet (taille max de 65535 octets)
            packet, addr = s.recvfrom(65535)
            print(f"Paquet ICMP reçu de {addr}")
            
            # Extraction des données UDP
            udp_data = extract_udp_from_icmp(packet)
            print(f"Données UDP extraites : {udp_data}")
            
            # Traitement ou renvoi des données UDP (par exemple, vers un serveur ou une application)
            # forward_udp_to_application(udp_data)  # Si tu veux renvoyer les données UDP ailleurs

def forward_udp_to_application(udp_data):
    """Optionnel : Redirige les données UDP extraites vers une application locale"""
    # Exemple pour envoyer le paquet UDP à une application locale (port 12345)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
        udp_socket.sendto(udp_data, ('127.0.0.1', 12345))
        print(f"Données UDP envoyées à l'application : {udp_data}")

# Lancer la réception des paquets ICMP et l'extraction du payload UDP
receive_icmp_packet()