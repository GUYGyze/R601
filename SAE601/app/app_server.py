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
SERVER_KEYS_DIR = "server_keys"
os.makedirs(SERVER_KEYS_DIR, exist_ok=True)

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
        f.write(server_keys/private_key)
    with open(SERVER_PUBLIC_KEY_PATH, 'w') as f:
        f.write(server_keys/public_key)
    return private_key, public_key

@app.route('/api/create_server_config', methods=['POST'])
def create_server_config():
    try:
        # Récupération des données du formulaire
        client_name = request.form.get('client_name')
        client_ip = request.form.get('client_ip')
        client_port = request.form.get('client_port')
        server_ip = request.form.get('server_ip')
        server_listen_port = request.form.get('server_listen_port')
        server_interface = request.form.get('server_interface')
        server_private_key = request.form.get('client_private_key')
        server_public_key = request.form.get('client_public_key')

        # Vérifier que toutes les données sont bien fournies
        if not all([server_ip, server_listen_port, server_interface, client_port, client_ip, client_name, server_private_key, server_public_key]):
            return jsonify({"success": False, "error": "Tous les champs sont requis"}), 400

        # Client public key reception => wireshark listenning (client_public_key)

        # Charger le template WireGuard
        config_template = """[Interface]
PrivateKey = {{ server_private_key }}
Address = {{ server_ip }}
ListenPort = {{ server_listen_port }}

{% for client in clients %}
[Peer]
PublicKey = {{ client.public_key }}
AllowedIPs = {{ client.ip }}/32
{% endfor %}"""

        # Générer la configuration avec Jinja2
        config_content = render_template_string(
            config_template,
            server_private_key=server_private_key,
            client_ip=client_ip,
            client_public_key=client_public_key,
            server_ip=server_ip,
            server_listen_port=server_listen_port
        )

        # Définir le chemin du fichier de configuration
        config_path = os.path.join(WG_CONFIG_PATH, f"{client_name}.conf")

        # Écrire la configuration dans un fichier
        with open(config_path, 'w') as config_file:
            config_file.write(config_content)

        return jsonify({"success": True, "message": "Configuration client créée avec succès", "file": config_path})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# Envoi de la clé publique via le script encap.py
# A changer
def send_server_key():
    subprocess.run(["python3", "encap.py", "server"])

# Routes Flask
@app.route('/')
def server_index():
    # Afficher la page du serveur
    server_private_key, server_public_key = save_server_keys()
    return render_template('server/index_server.html', server_public_key=server_public_key)

@app.route('/api/generate_server_keys')
def api_generate_server_keys():
    # Générer et retourner les clés du serveur
    server_private_key, server_public_key = save_server_keys()
    return jsonify({"private_key": server_private_key, "public_key": server_public_key})

@app.route('/api/send_public_key', methods=["POST"])
def api_send_server_key():
    # Exécuter le script pour envoyer la clé publique du serveur
    send_server_key()
    return jsonify({"success": True, "message": "Clé publique envoyée au client"})

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
