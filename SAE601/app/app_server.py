from flask import Flask, render_template, render_template_string, request, jsonify
import subprocess
import os
import socket
import struct
import random
import time
import uuid

app = Flask(__name__, template_folder='templates', static_folder='static')

# Chemin des fichiers de configuration WireGuard
WG_CONFIG_PATH = "/etc/wireguard/"
WG_INTERFACE = "wg0"
SERVER_KEYS_DIR = "server_keys"
SERVER_PRIVATE_KEY_PATH = os.path.join(SERVER_KEYS_DIR, "server_private_key")
SERVER_PUBLIC_KEY_PATH = os.path.join(SERVER_KEYS_DIR, "server_public_key")
icmp_reassembly_buffer = {}

os.makedirs(SERVER_KEYS_DIR, exist_ok=True)

### Pour rediriger des données UDP extraites vers une app
def forward_udp_to_application(udp_data, dest_ip='127.0.0.1', dest_port=12345):
    ###Redirige les données UDP extraites vers une application locale.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
        udp_socket.sendto(udp_data, (dest_ip, dest_port))
        print(f"Données UDP envoyées à {dest_ip}:{dest_port} -> {udp_data}")

#######################################
### Fonctions Désencapsulation ICMP ###
#######################################

def extract_udp_from_icmp(packet):
    ### Extrait le payload UDP encapsulé dans un paquet ICMP.
    ### Hypothèse : en-tête IP = 20 octets, en-tête ICMP = 8 octets
    ip_header_length = 20
    icmp_header_length = 8
    udp_payload = packet[ip_header_length + icmp_header_length:]  # Sauter IP + ICMP
    return udp_payload

def receive_icmp_packet(process_function=None):
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        s.bind(('0.0.0.0', 0))  # Écoute toutes interfaces
        print("En attente de paquets ICMP...")

        while True:
            packet, addr = s.recvfrom(65535)
            print(f"Paquet ICMP reçu de {addr}")
            udp_data = extract_udp_from_icmp(packet)

            if not udp_data.startswith(b'KEY:'):
                print("[!] Trame ICMP ignorée : tag non reconnu")
                continue

            payload = udp_data[4:]
            try:
                server_public_key = payload.decode('utf-8').strip()
                return server_public_key
            except UnicodeDecodeError:
                print("[!] Erreur de décodage de la clé publique")
                continue

            if process_function:
                process_function(udp_data)

### Fonction de traitement fragmentation 
def process_icmp_fragment(packet, udp_forward_ip='127.0.0.1', udp_forward_port=51820):
    udp_data = extract_udp_from_icmp(packet)
    if not udp_data.startswith(b'FRAG:'):
        print("[serveur] Trame ignorée (non fragmentée)")
        return

    try:
        header, data = udp_data.split(b':', 4)[:4], udp_data.split(b':', 4)[4]
        _, packet_id, index_str, total_str = [h.decode() for h in header]
        index, total = int(index_str), int(total_str)
    except Exception as e:
        print("[serveur] Erreur parsing header fragment:", e)
        return

    buffer = icmp_reassembly_buffer.setdefault(packet_id, {"total": total, "fragments": {}, "time": time.time()})
    buffer["fragments"][index] = data

    print(f"[serveur] Fragment {index+1}/{total} reçu pour ID {packet_id}")

    # Vérifier si tous les fragments sont là
    if len(buffer["fragments"]) == total:
        print(f"[serveur] Tous les fragments reçus pour ID {packet_id}, reconstruction...")
        full_data = b''.join(buffer["fragments"][i] for i in range(total))

        # Envoi au démon WireGuard local
        forward_udp_to_application(full_data, udp_forward_ip, udp_forward_port)

        # Nettoyage
        del icmp_reassembly_buffer[packet_id]

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

def send_icmp_packet(dest_ip, udp_data, tag=None):
    if tag:
        udp_data = tag.encode() + b':' + udp_data
    packet = create_icmp_packet(udp_data)
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        s.sendto(packet, (dest_ip, 0))

def send_udp_packet(dest_ip, udp_data):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(udp_data, (dest_ip, 51820))

def send_large_udp_over_icmp(dest_ip, udp_data, mtu=1024):
    fragment_size = mtu
    total_fragments = (len(udp_data) + fragment_size - 1) // fragment_size
    packet_id = str(uuid.uuid4())[:8]

    for i in range(total_fragments):
        fragment = udp_data[i * fragment_size : (i + 1) * fragment_size]
        header = f"FRAG:{packet_id}:{i}:{total_fragments}:".encode()
        payload = header + fragment
        send_icmp_packet(dest_ip, payload)
        print(f"[serveur] Fragment {i+1}/{total_fragments} envoyé avec ID {packet_id}")
        
##########################################################
### Capture du trafic UDP WireGuard avant le firewall  ###
##########################################################

def monitor_udp_wireguard_traffic(interface='eth0', dest_ip='192.0.2.1', wg_port=51820):
    print(f"[+] Surveillance de {interface} pour le trafic UDP WireGuard vers le port {wg_port}...")
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) as s:
        while True:
            packet = s.recvfrom(65535)[0]
            eth_proto = struct.unpack('!H', packet[12:14])[0]
            if eth_proto != 0x0800:
                continue
            ip_proto = packet[23]
            if ip_proto != 17:
                continue
            udp_segment = packet[34:]
            udp_dest_port = struct.unpack('!H', udp_segment[2:4])[0]
            if udp_dest_port == wg_port:
                print(f"[~] Paquet WireGuard intercepté sur {interface}, encapsulation ICMP...")
                send_icmp_packet(dest_ip, udp_segment)

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
    send_icmp_packet(dest_ip, key_data, tag='KEY')

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
    try:
        dest_ip = data.get("dest_ip")
    except:
        return jsonify({"success": False, "error": "Aucune adresse IP fournie"}), 400
    print(dest_ip)
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
        return jsonify({"success": True})
    except subprocess.CalledProcessError as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/start_udp_icmp_forwarding', methods=['POST'])
def start_udp_icmp_forwarding():
    data = request.get_json()
    interface = data.get('interface', 'eth0')
    dest_ip = data.get('dest_ip')
    wg_port = int(data.get('wg_port', 51820))

    if not dest_ip:
        return jsonify({"success": False, "error": "IP de destination requise"}), 400

    try:
        threading.Thread(target=monitor_udp_wireguard_traffic, args=(interface, dest_ip, wg_port), daemon=True).start()
        return jsonify({"success": True, "message": f"Redirection ICMP lancée depuis {interface} vers {dest_ip}"})
    except Exception as e:
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
