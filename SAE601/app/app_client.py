from flask import Flask, render_template, request, jsonify
import subprocess
import os
import socket
import struct
import random

app = Flask(__name__, template_folder='templates', static_folder='static')

# Chemin des fichiers de configuration WireGuard
WG_CONFIG_PATH = "/etc/wireguard/"
WG_INTERFACE = "wg0"
CLIENT_KEYS_DIR = "client_keys"
os.makedirs(CLIENT_KEYS_DIR, exist_ok=True)


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
        server_public_key = receive_icmp_packet()
        print(server_public_key)
        
        client_name = request.form.get('client_name')
        client_ip = request.form.get('client_ip')
        server_ip = request.form.get('server_ip')
        server_port = request.form.get('server_port')
        private_key = request.form.get('client_private_key')
        public_key = request.form.get('client_public_key')

        if not all([client_name, client_ip, server_ip, server_port, private_key, public_key]):
            return jsonify({"success": False, "error": "Tous les champs sont requis"}), 400

        config_template = """[Interface]
PrivateKey = {private_key}
Address = {client_ip}/24

[Peer]
PublicKey = {server_public_key}
Endpoint = {server_ip}:{server_port}
AllowedIPs = 0.0.0.0/0
"""
        config_content = config_template.format(
            private_key=private_key,
            client_ip=client_ip,
            client_public_key=public_key,
            server_ip=server_ip,
            server_port=server_port
        )

        config_path = os.path.join(WG_CONFIG_PATH, f"{client_name}.conf")

        with open(config_path, 'w') as config_file:
            config_file.write(config_content)

        return jsonify({"success": True, "message": "Configuration client créée avec succès", "file": config_path})
    
    except Exception as e:
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

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5001)
