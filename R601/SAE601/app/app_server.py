from flask import Flask, render_template, render_template_string, request, jsonify
import subprocess
import os
import socket
import struct
import random
import threading

app = Flask(__name__, template_folder='templates', static_folder='static')

# Chemin des fichiers de configuration WireGuard
WG_CONFIG_PATH = "/etc/wireguard/"
WG_INTERFACE = "wg0"
SERVER_KEYS_DIR = "server_keys"
SERVER_PRIVATE_KEY_PATH = os.path.join(SERVER_KEYS_DIR, "server_private_key")
SERVER_PUBLIC_KEY_PATH = os.path.join(SERVER_KEYS_DIR, "server_public_key")

os.makedirs(SERVER_KEYS_DIR, exist_ok=True)

######################
## Partie Handshake ##
######################

def is_wireguard_handshake(packet):
    """
    Détecte uniquement les paquets de handshake WireGuard (Initiation ou Response).
    """
    try:
        if len(packet) < 4:
            return False

        message_type = struct.unpack("!I", packet[:4])[0]

        if message_type == 1 and len(packet) >= 148:
            return True
        elif message_type == 2 and len(packet) >= 92:
            return True
        else:
            return False

    except Exception as e:
        print(f"Erreur lors de la détection handshake : {e}")
        return False

def encapsulate_wireguard_handshake(packet, dest_ip):
    """
    Encapsule un paquet de handshake WireGuard dans un paquet ICMP.
    """
    # Créer un paquet ICMP avec les données de handshake
    send_icmp_packet(dest_ip, packet)
    print(f"Handshake WireGuard encapsulé vers {dest_ip}")

def capture_and_encapsulate_handshake(port=51820):
    """
    Capture les paquets de handshake WireGuard et les encapsule.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP) as s:
        s.bind(('0.0.0.0', 0))
        print(f"Surveillance des paquets de handshake WireGuard sur le port {port}")
        
        # Dictionnaire pour suivre les paquets déjà encapsulés
        encapsulated_packets = {}
        
        while True:
            packet, addr = s.recvfrom(65535)
            ip_header = packet[:20]
            udp_header = packet[20:28]
            src_port, dest_port = struct.unpack('!HH', udp_header[:4])
            
            if dest_port == port:
                handshake_payload = packet[28:]
                
                # Générer un hash unique pour le paquet
                packet_hash = hash(handshake_payload)
                
                # Vérifier si c'est un paquet de handshake et s'il n'a pas déjà été encapsulé
                if is_wireguard_handshake(handshake_payload) and packet_hash not in encapsulated_packets:
                    # Stocker le hash du paquet pour éviter les doublons
                    encapsulated_packets[packet_hash] = True
                    
                    # Limiter la taille du dictionnaire pour éviter la croissance illimitée
                    if len(encapsulated_packets) > 1000:
                        encapsulated_packets.clear()
                    
                    # Choisir dynamiquement l'IP de destination
                    dest_ip = addr[0]  # IP source du paquet UDP
                    
                    # Encapsuler le paquet de handshake
                    encapsulate_wireguard_handshake(handshake_payload, dest_ip)
                    
def send_wireguard_handshake(handshake_data, port=51820, dest_ip='127.0.0.1'):
    """
    Réinjecte un paquet de handshake WireGuard via UDP.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(handshake_data, (dest_ip, port))
        print(f"Paquet de handshake WireGuard réinjecté vers {dest_ip}:{port}")

def receive_icmp_handshake(process_function=None):
    """
    Écoute les paquets ICMP contenant des handshakes WireGuard.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        s.bind(('0.0.0.0', 0))
        print("En attente de paquets ICMP de handshake...")

        while True:
            packet, addr = s.recvfrom(65535)
            handshake_data = extract_udp_from_icmp(packet)
            
            # Vérifier que c'est bien un paquet de handshake
            if is_wireguard_handshake(handshake_data):
                print(f"Handshake WireGuard reçu de {addr}")
                
                # Réinjecter le paquet ou appeler une fonction de traitement
                send_wireguard_handshake(handshake_data)
                
                if process_function:
                    process_function(handshake_data)

def start_handshake_capture():
    """
    Démarre un thread pour capturer les handshakes.
    """
    handshake_thread = threading.Thread(target=capture_and_encapsulate_handshake)
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
    :param process_function: fonction à appliquer sur les données UDP extraites
    """
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        s.bind(('0.0.0.0', 0))  # Écoute toutes interfaces
        print("En attente de paquets ICMP...")

        while True:
            packet, addr = s.recvfrom(65535)
            print(f"Paquet ICMP reçu de {addr}")
            udp_data = extract_udp_from_icmp(packet)
            print(f"Données UDP extraites : {udp_data}")
            client_public_key = udp_data.decode('utf-8').strip()
            print(f"Clé publique reçue : {client_public_key}")
            return client_public_key

            if process_function:
                process_function(udp_data)

##############################################
### Fonctions Capture & Envoi Paquets ICMP ###
##############################################

def capture_wireguard_udp_packet(port=51820):
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP) as s:
        s.bind(('0.0.0.0', 0))
        print(f"Attente d'un paquet WireGuard sur le port {port}...")
        while True:
            packet, addr = s.recvfrom(65535)
            ip_header = packet[:20]
            udp_header = packet[20:28]
            src_port, dest_port = struct.unpack('!HH', udp_header[:4])
            if dest_port == port:
                print(f"Paquet UDP WireGuard capturé de {addr}")
                return packet[28:]  # Seulement le payload UDP

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

# Sauvegarde des clés publiques et privées du serveur
def save_server_keys():
    private_key, public_key = generate_keys()
    with open(SERVER_PRIVATE_KEY_PATH, 'w') as f:
        f.write(private_key)
    with open(SERVER_PUBLIC_KEY_PATH, 'w') as f:
        f.write(public_key)
    return private_key, public_key

@app.route('/api/create_server_config', methods=['POST'])
def create_server_config():
    try:
        client_public_key = receive_icmp_packet()

        # Récupération des données du formulaire
        client_name = request.form.get('client_name')
        client_ip = request.form.get('client_ip')
        client_endpoint = request.form.get('client_endpoint')
        client_port = request.form.get('client_port')
        
        server_ip = request.form.get('server_ip')
        server_listen_port = request.form.get('server_listen_port')
        server_interface = request.form.get('server_interface')
        server_endpoint = request.form.get('server_endpoint')
        
        server_private_key = request.form.get('server_private_key')
        server_public_key = request.form.get('server_public_key')
        
        # Vérifier que toutes les données sont bien fournies
        if not all([server_ip, server_listen_port, server_interface, client_ip, client_name, server_private_key, server_public_key]):
            return jsonify({"success": False, "error": "Tous les champs sont requis"}), 400

        # Client public key reception => wireshark listenning (client_public_key)

        # Charger le template WireGuard
        config_template = """[Interface]
PrivateKey = {{ server_private_key }}
SaveConfig = true
Address = {{ server_ip }}/24
ListenPort = {{ server_listen_port }}

[Peer]
PublicKey = {{ client_public_key }}
AllowedIPs = {{ client_ip }}/32
Endpoint = {{ client_endpoint }}:{{ client_port }}
"""

        # Générer la configuration avec Jinja2
        config_content = render_template_string(
            config_template,
            server_private_key=server_private_key,
            client_ip=client_ip,
            client_endpoint=client_endpoint,
            client_public_key=client_public_key,
            server_ip=server_ip,
            client_port=client_port,
            server_listen_port=server_listen_port,
        )

        # Définir le chemin du fichier de configuration
        config_path = os.path.join(WG_CONFIG_PATH, f"{WG_INTERFACE}.conf")

        # Écrire la configuration dans un fichier
        with open(config_path, 'w') as config_file:
            config_file.write(config_content)

        return jsonify({"success": True, "message": "Configuration client créée avec succès", "file": config_path})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

def send_server_key(client_ip):
    # 1) Lire la clé publique sauvegardée
    public_key_path = os.path.join(SERVER_KEYS_DIR, "server_public_key")
    if not os.path.exists(public_key_path):
        raise FileNotFoundError("Clé publique introuvable. Générez d'abord les clés.")

    with open(public_key_path, 'r') as f:
        public_key = f.read().strip()

    # 2) Encoder la clé publique en bytes
    key_data = public_key.encode('utf-8')

    # 3) Envoyer via ICMP
    send_icmp_packet(client_ip, key_data)

# Routes Flask
@app.route('/')
def server_index():
    # Afficher la page du serveur
    return render_template('server/index_server.html')

@app.route('/api/generate_keys')
def api_generate_server_keys():
    server_private_key, server_public_key = save_server_keys()
    return jsonify({
        "success": True,
        "private_key": server_private_key,
        "public_key": server_public_key
    })

@app.route('/api/send_public_key', methods=["POST"])
def api_send_server_key():
    data = request.get_json()
    dest_ip = data.get("dest_ip")

    if not dest_ip:
        return jsonify({"success": False, "error": "Aucune adresse IP fournie"}), 400  # Ajoute une vérification

    try:
        send_server_key(dest_ip)
        return jsonify({"success": True, "message": f"Clé publique envoyée en ICMP vers {dest_ip}"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500  # Capture les erreurs

@app.route('/api/start_tunnel', methods=['GET'])
def start_tunnel():
    client_ip = request.args.get('ip')
    if not client_ip:
        return jsonify({"success": False, "error": "IP du client manquante"}), 400
    
    try:
        subprocess.run(["wg-quick", "up", WG_INTERFACE], check=True)
        start_handshake_capture()
        start_handshake_receive()
        return jsonify({"success": True})
    except subprocess.CalledProcessError as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/stop_tunnel', methods=['GET'])
def stop_tunnel():
    client_ip = request.args.get('ip')
    if not client_ip:
        return jsonify({"success": False, "error": "IP du client manquante"}), 400
    
    try:
        subprocess.run(["wg-quick", "down", WG_INTERFACE], check=True)
        return jsonify({"success": True})
    except subprocess.CalledProcessError as e:
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
