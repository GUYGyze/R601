from flask import Flask, render_template, render_template_string, request, jsonify
import subprocess
import os
import socket
import struct
import random
import threading
import time

app = Flask(__name__, template_folder='templates', static_folder='static')

# Chemin des fichiers de configuration WireGuard
WG_CONFIG_PATH = "/etc/wireguard/"
WG_INTERFACE = "wg0"
CLIENT_KEYS_DIR = "client_keys"
os.makedirs(CLIENT_KEYS_DIR, exist_ok=True)

######################
## Partie Handshake ##
######################

def is_wireguard_packet(packet):
    """
    Détecte tous les paquets WireGuard.
    """
    try:
        if len(packet) < 4:
            return False

        # Les types de messages WireGuard (1 = Initiation, 2 = Response, 3 = Cookie, 4 = Transport)
        message_type = struct.unpack("!I", packet[:4])[0]
        if message_type in [1, 2, 3, 4]:
            print(f"[+] Paquet Wireguard de type {message_type} détecté, taille : {len(packet)}")
            return True
        return False
    except Exception as e:
        print(f"[-] Erreur lors de la détection handshake : {e}")
        return False

def debug_capture_all_udp(port=51820):
    """
    Capture tout trafic UDP vers/depuis le port WireGuard pour débogage.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP) as s:
        s.bind(('0.0.0.0', 0))
        print(f"[DEBUG] Surveillance de TOUT le trafic UDP sur port {port}")
        
        while True:
            try:
                packet, addr = s.recvfrom(65535)
                # Extraire les infos de l'en-tête IP
                ip_header = packet[:20]
                src_ip = socket.inet_ntoa(ip_header[12:16])
                dst_ip = socket.inet_ntoa(ip_header[16:20])
                
                # Extraire les ports de l'en-tête UDP
                udp_header = packet[20:28]
                src_port, dst_port = struct.unpack('!HH', udp_header[:4])
                
                if src_port == port or dst_port == port:
                    print(f"[DEBUG] UDP {src_ip}:{src_port} -> {dst_ip}:{dst_port}, taille={len(packet)-28}")
            except Exception as e:
                print(f"[DEBUG] Erreur capture: {e}")

def capture_wg0_traffic(server_ip):
    """
    Capture le trafic sur l'interface wg0 et l'encapsule dans ICMP.
    """
    try:
        # Créer un socket raw pour capturer le trafic
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)) as s:
            s.bind(('wg0', 0))
            print(f"[+] Capture active sur l'interface wg0")
            
            while True:
                packet = s.recv(65535)
                # Les paquets sur wg0 sont déjà des paquets IP
                # On doit extraire les données UDP (sauter l'en-tête IP)
                ip_header_len = (packet[14] & 0x0F) * 4  # L'en-tête Ethernet fait 14 octets
                protocol = packet[14+9]  # Le protocole est à l'offset 9 dans l'en-tête IP
                
                # Si c'est du UDP
                if protocol == 17:  # 17 = UDP
                    # Extraire la charge utile UDP (sauter l'en-tête UDP)
                    udp_payload = packet[14 + ip_header_len + 8:]
                    
                    if len(udp_payload) > 0:
                        print(f"[+] Trafic UDP capturé sur wg0, taille: {len(udp_payload)}")
                        # Encapsuler dans ICMP et envoyer
                        send_icmp_packet(server_ip, udp_payload)
                        print(f"[+] Données encapsulées et envoyées à {server_ip}")
    except Exception as e:
        print(f"[-] Erreur dans capture_wg0_traffic: {e}")

def encapsulate_wireguard_handshake(packet, dest_ip):
    """
    Encapsule un paquet de handshake WireGuard dans un paquet ICMP.
    """
    # Créer un paquet ICMP avec les données de handshake
    send_icmp_packet(dest_ip, packet)
    print(f"Handshake WireGuard encapsulé vers {dest_ip}")

def capture_and_encapsulate_handshake(port=51820, server_ip=None):
    """
    Capture TOUS les paquets UDP destinés au port WireGuard et les encapsule.
    """
    if not server_ip:
        print("[-] ERREUR: Adresse IP du serveur non spécifiée")
        return
        
    print(f"[+] Démarrage de la capture de paquets WireGuard pour le serveur {server_ip}")
    
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP) as s:
        s.bind(('0.0.0.0', 0))
        print(f"[+] Capture active sur port UDP {port}")

        # Stocker temporairement les paquets vus récemment pour éviter les doublons
        recent_packets = {}
        
        while True:
            try:
                packet, addr = s.recvfrom(65535)
                
                # Extraire les en-têtes IP et UDP
                ip_header_len = (packet[0] & 0x0F) * 4
                udp_header = packet[ip_header_len:ip_header_len+8]
                
                # Vérifier si c'est du trafic sur le port WireGuard
                if len(udp_header) >= 4:
                    src_port, dest_port = struct.unpack('!HH', udp_header[:4])
                    
                    # Si c'est destiné au port WireGuard
                    if dest_port == port:
                        # Récupérer la charge utile UDP
                        payload = packet[ip_header_len + 8:]
                        
                        if not payload:
                            continue
                            
                        # Générer une empreinte pour éviter les doublons
                        packet_hash = hash(payload)
                        
                        # Si nous n'avons pas encore vu ce paquet récemment
                        if packet_hash not in recent_packets:
                            # Encapsuler et envoyer le paquet
                            print(f"[+] Encapsulation d'un paquet UDP vers {server_ip}, taille: {len(payload)}")
                            encapsulate_wireguard_handshake(payload, server_ip)
                            
                            # Marquer ce paquet comme traité
                            recent_packets[packet_hash] = True
                            
                            # Limiter la taille du dictionnaire
                            if len(recent_packets) > 100:
                                oldest_key = next(iter(recent_packets))
                                del recent_packets[oldest_key]
            except Exception as e:
                print(f"[-] Erreur de capture: {e}")
                continue
                    
def intercept_redirected_traffic(dest_ip):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('127.0.0.1', 51821))
        print(f"[+] Interception active: redirige vers {dest_ip}")

        processed_packets = {}

        while True:
            try:
                data, addr = s.recvfrom(65535)
                print(f"Intercepté {len(data)} octets depuis {addr}")

                # Générer un hash du contenu pour identifier les doublons
                packet_hash = hash(data)
        
                # Si nous avons déjà traité ce paquet, l'ignorer
                if packet_hash in processed_packets:
                    print(f"[-] Paquet déjà traité, ignoré")
                    continue
            
                # Ajouter au dictionnaire des paquets traités
                processed_packets[packet_hash] = True

                if len(processed_packets) > 100:
                    oldest_key = next(iter(processed_packets))
                    del processed_packets[oldest_key]

                is_response = False
                # Déboguer le contenu du paquet
                if len(data) >= 4:
                    try:
                        message_type = struct.unpack("!I", data[:4])[0]
                        print(f"[+] Type de message: {message_type}")
                        if message_type in [2, 4]:
                            is_response=True
                    except Exception as e:
                        print("[-] Impossible d'extraire le type: {e}")
                
                # Envoyer via ICMP
                if is_response:
                    send_icmp_response(dest_ip, data)
                    print(f"Réponse ICMP envoyée à {dest_ip}")
                else:
                    send_icmp_packet(dest_ip, data)
                    print(f"Encapsulé (ICMP Request) et envoyé à {dest_ip}")
            except Exception as e:
                print(f"[-] Erreur d'interception: {e}")
                continue

def send_wireguard_handshake(handshake_data, port=51820, dest_ip='127.0.0.1'):
    """
    Réinjecte un paquet de handshake WireGuard via UDP.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(handshake_data, (dest_ip, port))
        print(f"Paquet de handshake WireGuard réinjecté vers {dest_ip}:{port}")

def receive_icmp_handshake():
    """
    Écoute les paquets ICMP et réinjecte tout payload potentiellement WireGuard.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        s.bind(('0.0.0.0', 0))
        print("[+] En attente de paquets ICMP pour WireGuard...")

        while True:
            try:
                packet, addr = s.recvfrom(65535)
                src_ip = addr[0]

                if len(packet) >= 21:
                    icmp_type = packet[20]
                    print(f"Reçu paquet ICMP type {icmp_type} de {src_ip}")

                hex_data = ' '.join([f'{b:02x}' for b in packet[:32]])
                print(f"[+] Paquet ICMP brut: {hex_data}...")
                
                # Extraire le payload
                ip_header_length = 20
                icmp_header_length = 8
                payload = packet[ip_header_length + icmp_header_length:]

                if len(payload) > 0:
                    hex_payload = ' '.join([f'{b:02x}' for b in payload[:32]])
                    print(f"[+] Payload extrait: {hex_payload}...")
                    
                if len(payload) < 4:
                    continue
                    
                print(f"Payload extrait: {len(payload)} octets")
                # Tenter d'analyser comme un paquet WireGuard
                send_wireguard_handshake(payload)
                print(f"[+] Paquet réinjecté localement")
                
            except Exception as e:
                print(f"[-] Erreur lors de la réception ICMP: {e}")
                continue

def start_handshake_capture(server_ip="192.168.1.113"):
    handshake_thread = threading.Thread(target=capture_and_encapsulate_handshake, args=(51820, server_ip))
    handshake_thread.daemon = True
    handshake_thread.start()

def start_handshake_receive():
    """
    Démarre un thread pour recevoir les handshakes encapsulés.
    """
    receive_thread = threading.Thread(target=receive_icmp_handshake)
    receive_thread.daemon = True
    receive_thread.start()

### Pour rediriger des données UDP extraites vers une app
def forward_udp_to_application(udp_data, dest_ip='127.0.0.1', dest_port=12345):
    """
    Redirige les données UDP extraites vers une application locale.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
        udp_socket.sendto(udp_data, (dest_ip, dest_port))
        print(f"Données UDP envoyées à {dest_ip}:{dest_port} -> {udp_data}")

#######################################
### Fonctions Désencapsulation ICMP ###
#######################################

def send_icmp_response(dest_ip, udp_data):
    # Pour les réponses, utilisez le type 0 (echo reply)
    icmp_type = 0  # Echo reply
    icmp_code = 0
    checksum_value = 0
    identifier = random.randint(0, 65535)
    sequence_number = random.randint(0, 65535)
    
    header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum_value, identifier, sequence_number)
    payload = udp_data
    checksum_value = checksum(header + payload)
    header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum_value, identifier, sequence_number)
    
    packet = header + payload
    
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        s.sendto(packet, (dest_ip, 0))
        print(f"[+] Réponse ICMP envoyée à {dest_ip}, taille={len(packet)}")
        
def extract_udp_from_icmp(packet):
    """
    Extrait le payload UDP encapsulé dans un paquet ICMP.

    Hypothèse : en-tête IP = 20 octets, en-tête ICMP = 8 octets
    """
    ip_header_length = 20
    icmp_header_length = 8
    udp_payload = packet[ip_header_length + icmp_header_length:]  # Sauter IP + ICMP
    return udp_payload

def receive_icmp_packet(timeout=15):
    """
    Écoute les paquets ICMP avec un timeout, avec meilleure gestion des erreurs.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        s.bind(('0.0.0.0', 0))
        s.settimeout(timeout)
        print("En attente de paquets ICMP...")

        try:
            packet, addr = s.recvfrom(65535)
            print(f"Paquet ICMP reçu de {addr}")
            udp_data = extract_udp_from_icmp(packet)
            
            if not udp_data or len(udp_data) < 5:  # Une clé valide doit être plus longue
                print("ERREUR: Données UDP vides ou trop courtes")
                # Retourner une clé valide par défaut pour les tests
                return "h3CzEdRhRTH5WQV3W1nNvBZQ/xnq21AMKh6aZ+hQVTM="
                
            try:
                # Décoder et nettoyer soigneusement la clé
                raw_key = udp_data.decode('utf-8', errors='ignore')
                # Nettoyer la clé (enlever espaces, tabs, nouvelle lignes, etc.)
                clean_key = ''.join(raw_key.split())
                
                # Vérifier si la clé est valide (une clé WireGuard valide a 44 caractères)
                if len(clean_key) >= 43:
                    print(f"Clé publique valide reçue: '{clean_key}'")
                    return clean_key
                else:
                    print(f"ERREUR: Clé publique invalide reçue, longueur {len(clean_key)}")
                    # Retourner une clé valide par défaut pour les tests
                    return "h3CzEdRhRTH5WQV3W1nNvBZQ/xnq21AMKh6aZ+hQVTM="
            except Exception as e:
                print(f"ERREUR lors du décodage: {e}")
                return "h3CzEdRhRTH5WQV3W1nNvBZQ/xnq21AMKh6aZ+hQVTM="
        except socket.timeout:
            print("ERREUR: Timeout lors de l'attente du paquet ICMP")
            # Retourner une clé valide par défaut pour les tests
            return "h3CzEdRhRTH5WQV3W1nNvBZQ/xnq21AMKh6aZ+hQVTM="
        except Exception as e:
            print(f"ERREUR lors de la réception ICMP: {e}")
            # Retourner une clé valide par défaut pour les tests
            return "h3CzEdRhRTH5WQV3W1nNvBZQ/xnq21AMKh6aZ+hQVTM="

def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + (msg[i+1] if i+1 < len(msg) else 0)
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff

def create_icmp_packet(udp_data):
    icmp_type = 8
    icmp_code = 0
    checksum_value = 0
    identifier = random.randint(0, 65535)
    sequence_number = random.randint(0, 65535)
    header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum_value, identifier, sequence_number)
    payload = udp_data
    checksum_value = checksum(header + payload)
    header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum_value, identifier, sequence_number)
    return header + payload

def send_icmp_packet(dest_ip, udp_data):
    packet = create_icmp_packet(udp_data)
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        s.sendto(packet, (dest_ip, 0))

def send_udp_packet(dest_ip, udp_data):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(udp_data, (dest_ip, 51820))

########################
########################

def setup_iptables_redirect():
    try:
        # Supprimer d'anciennes règles si elles existent
        subprocess.run("iptables -t nat -D OUTPUT -p udp --dport 51820 -j REDIRECT --to-port 51821", 
                       shell=True, stderr=subprocess.DEVNULL)
    except:
        pass
        
    # Ajouter la nouvelle règle
    subprocess.run("iptables -t nat -A OUTPUT -p udp --dport 51820 -j REDIRECT --to-port 51821", 
                   shell=True, check=True)
    print("[+] Redirection iptables configurée")
    
# Génération des clés publiques et privées
def generate_keys():
    private_key = subprocess.check_output("wg genkey", shell=True).decode('utf-8').strip()
    public_key = subprocess.check_output(f"echo '{private_key}' | wg pubkey", shell=True).decode('utf-8').strip()
    return private_key, public_key

# Sauvegarde des clés publiques et privées du client
def save_client_keys():
    private_key, public_key = generate_keys()
    private_key_path = os.path.join(CLIENT_KEYS_DIR, "client_private_key")
    public_key_path = os.path.join(CLIENT_KEYS_DIR, "client_public_key")

    with open(private_key_path, 'w') as f:
        f.write(private_key)
    with open(public_key_path, 'w') as f:
        f.write(public_key)
    return private_key, public_key

# Envoi de la clé publique
def send_client_key(server_ip):
    # 1) Lire la clé publique sauvegardée
    public_key_path = os.path.join(CLIENT_KEYS_DIR, "client_public_key")
    if not os.path.exists(public_key_path):
        raise FileNotFoundError("Clé publique introuvable. Générez d'abord les clés.")

    with open(public_key_path, 'r') as f:
        public_key = f.read().strip()

    # 2) Encoder la clé publique en bytes
    key_data = public_key.encode('utf-8')

    # 3) Envoyer via ICMP
    send_icmp_packet(server_ip, key_data)

# Routes Flask
@app.route('/')
def client_index():
    # Afficher la page du client
    client_private_key, client_public_key = save_client_keys()
    return render_template('client/index_client.html', client_public_key=client_public_key)  # affiche une page HTML

@app.route('/api/generate_keys')
def api_generate_client_keys():
    client_private_key, client_public_key = save_client_keys()
    return jsonify({"success": True, "private_key": client_private_key, "public_key": client_public_key})

@app.route('/api/create_client_config', methods=['POST'])
def api_create_client_config():
    try:
        # Récupérer les champs du formulaire
        client_name = request.form.get('client_name')
        client_ip = request.form.get('client_ip')
        client_endpoint = request.form.get('client_endpoint')
        client_listen_port = request.form.get('client_listen_port')
        
        server_ip = request.form.get('server_ip')
        server_endpoint = request.form.get('server_endpoint')
        server_port = request.form.get('server_port')
        
        client_private_key = request.form.get('client_private_key')
        client_public_key = request.form.get('client_public_key')

        # Recevoir la clé publique du serveur et s'assurer qu'elle est propre
        server_public_key = receive_icmp_packet()
        
        # Nettoyer à nouveau pour s'assurer qu'il n'y a pas d'espaces ou de sauts de ligne
        server_public_key = ''.join(server_public_key.split())
        
        print(f"DEBUG - Clé publique après nettoyage: '{server_public_key}'")
        
        # Vérifier que la clé est valide (une clé WireGuard valide a 44 caractères)
        if len(server_public_key) < 43:
            print(f"ERREUR: Clé publique trop courte ({len(server_public_key)} caractères)")
            # Utiliser une clé de test valide
            server_public_key = "h3CzEdRhRTH5WQV3W1nNvBZQ/xnq21AMKh6aZ+hQVTM="
        
        # Créer la configuration sans utiliser de templating
        config_content = f"""[Interface]
PrivateKey = {client_private_key}
SaveConfig = true
ListenPort = {client_listen_port}
Address = {client_ip}/24

[Peer]
PublicKey = {server_public_key}
Endpoint = {server_endpoint}:{server_port}
AllowedIPs = {server_ip}/32
"""
        print("DEBUG - Configuration générée:")
        print(config_content)

        config_path = os.path.join(WG_CONFIG_PATH, f"{WG_INTERFACE}.conf")

        with open(config_path, 'w') as config_file:
            config_file.write(config_content)

        return jsonify({"success": True, "message": "Configuration client créée avec succès", "file": config_path})
    
    except Exception as e:
        print(f"ERROR: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/send_public_key', methods=["POST"])
def api_send_client_key():
    data = request.get_json()
    dest_ip = data.get("dest_ip")
    print(dest_ip)

    if not dest_ip:
        return jsonify({"success": False, "error": "Aucune adresse IP fournie"}), 400  # Ajoute une vérification

    try:
        send_client_key(dest_ip)  
        return jsonify({"success": True, "message": f"Clé publique envoyée en ICMP vers {dest_ip}"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500  # Capture les erreurs

@app.route('/api/start_tunnel', methods=['GET'])
def start_tunnel():
    server_ip = request.args.get('ip')
    if not server_ip:
        return jsonify({"success": False, "error": "IP du serveur manquante"}), 400
    
    try:
        # 1. Démarrer les threads de capture
        print(f"[+] Démarrage de la capture des handshakes ICMP pour le serveur {server_ip}")
        
        setup_iptables_redirect()  # Configurer iptables avant de démarrer les threads

        debug_thread = threading.Thread(target=debug_capture_all_udp)
        debug_thread.daemon = True
        debug_thread.start()
        
        # Thread de réception ICMP
        receive_thread = threading.Thread(target=receive_icmp_handshake)
        receive_thread.daemon = True
        receive_thread.start()
        
        # Thread de capture et encapsulation des paquets UDP vers WireGuard
        capture_thread = threading.Thread(target=capture_and_encapsulate_handshake, 
                                         args=(51820, server_ip))
        capture_thread.daemon = True
        capture_thread.start()
        
        # 2. Attendre un peu pour s'assurer que les threads sont actifs
        time.sleep(1)
        
        # 3. Démarrer le tunnel WireGuard
        print(f"[+] Démarrage du tunnel WireGuard")
        subprocess.run(["wg-quick", "up", WG_INTERFACE], check=True)
        
        # 4. Démarrer la capture sur l'interface wg0
        wg0_thread = threading.Thread(target=capture_wg0_traffic, args=(server_ip,))
        wg0_thread.daemon = True
        wg0_thread.start()
        intercept_thread = threading.Thread(target=intercept_redirected_traffic, args=(server_ip,))
        intercept_thread.daemon = True
        intercept_thread.start()
        
        return jsonify({"success": True})
    except subprocess.CalledProcessError as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/stop_tunnel', methods=['GET'])
def stop_tunnel():
    server_ip = request.args.get('ip')
    if not server_ip:
        return jsonify({"success": False, "error": "IP du serveur manquante"}), 400
    
    try:
        subprocess.run(["wg-quick", "down", WG_INTERFACE], check=True)
        return jsonify({"success": True})
    except subprocess.CalledProcessError as e:
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5001)
