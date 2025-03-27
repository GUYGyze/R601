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

def is_wireguard_handshake(packet):
    """
    Détecte tous les paquets WireGuard avec une logique plus souple.
    """
    try:
        if len(packet) < 4:
            return False

        # Les types de messages WireGuard (1 = Initiation, 2 = Response, 3 = Cookie, 4 = Transport)
        message_type = struct.unpack("!I", packet[:4])[0]
        
        # Afficher plus d'informations de diagnostic
        if message_type in [1, 2, 3, 4]:
            print(f"[+] Paquet WireGuard de type {message_type} détecté, taille: {len(packet)}")
            return True
        
        return False
    except Exception as e:
        print(f"[-] Erreur lors de la détection handshake : {e}")
        return False

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
                
                # Extraire le payload
                ip_header_length = 20
                icmp_header_length = 8
                payload = packet[ip_header_length + icmp_header_length:]
                
                if len(payload) < 4:
                    continue
                    
                # Tenter d'analyser comme un paquet WireGuard
                try:
                    message_type = struct.unpack("!I", payload[:4])[0]
                    if message_type in [1, 2, 3, 4]:
                        print(f"[+] Paquet ICMP reçu de {src_ip} contenant un message WireGuard type {message_type}")
                        # Réinjecter dans WireGuard local
                        send_wireguard_handshake(payload)
                        print(f"[+] Paquet réinjecté localement")
                except:
                    # Ce n'est pas un paquet WireGuard
                    continue
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

def extract_udp_from_icmp(packet):
    """
    Extrait le payload UDP encapsulé dans un paquet ICMP.

    Hypothèse : en-tête IP = 20 octets, en-tête ICMP = 8 octets
    """
    ip_header_length = 20
    icmp_header_length = 8
    udp_payload = packet[ip_header_length + icmp_header_length:]  # Sauter IP + ICMP
    return udp_payload

def receive_icmp_packet(process_function=None):
    """
    Écoute les paquets ICMP, extrait le payload UDP, et applique une fonction dessus si besoin.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        s.bind(('0.0.0.0', 0))  # Écoute toutes interfaces
        s.settimeout(15)  # Timeout de 15 secondes
        print("En attente de paquets ICMP...")

        try:
            packet, addr = s.recvfrom(65535)
            print(f"Paquet ICMP reçu de {addr}")
            udp_data = extract_udp_from_icmp(packet)
            print(f"Données UDP extraites : {udp_data}")
            
            if not udp_data:
                print("ERREUR: Données UDP vides")
                return "BASE64_INVALID_KEY"  # Retourner une valeur non vide pour éviter l'erreur
                
            try:
                client_public_key = udp_data.decode('utf-8').strip()
                print(f"Clé publique reçue : '{client_public_key}'")
                return client_public_key
            except UnicodeDecodeError:
                print("ERREUR: Impossible de décoder les données UDP en UTF-8")
                # Retourner une clé par défaut ou une valeur encodée en base64
                return "BASE64_INVALID_KEY"
        except socket.timeout:
            print("ERREUR: Timeout lors de l'attente du paquet ICMP")
            return "BASE64_TIMEOUT_KEY"  # Retourner une valeur non vide pour éviter l'erreur
        except Exception as e:
            print(f"ERREUR lors de la réception ICMP: {e}")
            return "BASE64_ERROR_KEY"  # Retourner une valeur non vide pour éviter l'erreur

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

        # Vérifier que tous les champs sont remplis
        if not all([client_name, client_ip, server_ip, server_port, client_endpoint, server_endpoint, client_listen_port, client_private_key, client_public_key]):
            return jsonify({"success": False, "error": "Tous les champs sont requis"}), 400

        # Essayer de recevoir la clé publique du serveur
        server_public_key = receive_icmp_packet()
        if not server_public_key or len(server_public_key) < 10:
            return jsonify({"success": False, "error": "Impossible de recevoir la clé publique du serveur"}), 500

        print(f"DEBUG - Clé publique reçue: '{server_public_key}'")
        
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
        # 1. Démarrer d'abord la capture des handshakes
        print(f"[+] Démarrage de la capture des handshakes ICMP pour le serveur {server_ip}")
        
        # Démarrer thread de réception ICMP
        receive_thread = threading.Thread(target=receive_icmp_handshake)
        receive_thread.daemon = True
        receive_thread.start()
        
        # Démarrer thread de capture et encapsulation
        capture_thread = threading.Thread(target=capture_and_encapsulate_handshake, 
                                         args=(51820, server_ip))
        capture_thread.daemon = True
        capture_thread.start()
        
        # 2. Attendre un peu pour s'assurer que les threads sont actifs
        time.sleep(1)
        
        # 3. Ensuite démarrer le tunnel WireGuard
        print(f"[+] Démarrage du tunnel WireGuard")
        print(f"DEBUG - server_ip: '{server_ip}'")
        print(f"DEBUG - AllowedIPs : '{server_ip}/32'")
        subprocess.run(["wg-quick", "up", WG_INTERFACE], check=True)
        
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
