from flask import Flask, render_template, request, jsonify
import subprocess
import os
import socket
import struct
import random

app = Flask(__name__)

# Chemin des fichiers de configuration WireGuard
WG_CONFIG_PATH = "/etc/wireguard/wg0.conf"
WG_INTERFACE = "wg0"
CLIENT_PRIVATE_KEY_PATH = "client_privatekey"
CLIENT_PUBLIC_KEY_PATH = "client_publickey"

os.makedirs(WG_CONFIG_PATH, exist_ok=True) # vérifier que le dossier de configuration existe

############################################
### Fonctions Capture & Envoi Paquets ICMP ###
############################################

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

# Génération des clés publiques et privées
def generate_keys():
    private_key = subprocess.check_output("wg genkey", shell=True).decode('utf-8').strip()
    public_key = subprocess.check_output(f"echo '{private_key}' | wg pubkey", shell=True).decode('utf-8').strip()
    return private_key, public_key

# Sauvegarde des clés publiques et privées du client
# A changer la génération de clés doit se faire lors d'une action sur un bouton
def save_client_keys():
    private_key, public_key = generate_keys()
    with open(CLIENT_PRIVATE_KEY_PATH, 'w') as f:
        f.write(private_key)
    with open(CLIENT_PUBLIC_KEY_PATH, 'w') as f:
        f.write(public_key)
    return private_key, public_key

# Envoi de la clé publique via le script encap.py
# a changer
def send_client_key():
    subprocess.run(["python3", "encap.py", "client"])

# Routes Flask
@app.route('/client')
def client_index():
    # Afficher la page du client
    client_private_key, client_public_key = save_client_keys()
    return render_template('client/index_client.html', client_public_key=client_public_key)  # affiche une page HTML
    
@app.route('/api/create_client_config', methods=['POST'])
def api_create_client_config():
    try:
        # Récupération des données du formulaire
        client_name = request.form.get('client_name')
        client_ip = request.form.get('client_ip')
        server_endpoint = request.form.get('server_endpoint')
        server_port = request.form.get('server_port')
        private_key = request.form.get('private_key')
        public_key = request.form.get('public_key')

        # Vérifier que toutes les données sont bien fournies
        if not all([client_name, client_ip, server_endpoint, server_port, private_key, public_key]):
            return jsonify({"success": False, "error": "Tous les champs sont requis"}), 400

        # Charger le template WireGuard
        config_template = """[Interface]
PrivateKey = {{ client_private_key }}
Address = {{ client_ip }}/24

[Peer]
PublicKey = {{ server_public_key }}
Endpoint = {{ server_endpoint }}:{{ server_port }}
AllowedIPs = 0.0.0.0/0
"""

        # Générer la configuration avec Jinja2
        config_content = render_template_string(
            config_template,
            client_private_key=private_key,
            client_ip=client_ip,
            server_public_key=public_key,
            server_endpoint=server_endpoint,
            server_port=server_port
        )

        # Définir le chemin du fichier de configuration
        config_path = os.path.join(WG_CONFIG_PATH, f"{client_name}.conf")

        # Écrire la configuration dans un fichier
        with open(config_path, 'w') as config_file:
            config_file.write(config_content)

        return jsonify({"success": True, "message": "Configuration client créée avec succès", "file": config_path})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/generate_keys')  # Récupérer le json des clés  client en URL
def api_generate_client_keys():
    # Générer et retourner les clés du client
    client_private_key, client_public_key = save_client_keys()
    return jsonify({"private_key": client_private_key, "public_key": client_public_key})

#A changer
@app.route('/api/send_puclic_key', methods=["POST"])
def api_send_client_key():
    # Exécuter le script pour envoyer la clé publique du client
    send_client_key()
    return jsonify({"success": True, "message": "Clé publique envoyée au serveur"})

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5001)
