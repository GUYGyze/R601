from flask import Flask, render_template, render_template_string, request, jsonify
import subprocess
import os
import socket
import struct
import random
import threading
import uuid
import time
import threading

app = Flask(__name__, template_folder='templates', static_folder='static')

# Chemin des fichiers de configuration WireGuard
WG_CONFIG_PATH = "/etc/wireguard/"
WG_INTERFACE = "wg0"
CLIENT_KEYS_DIR = "client_keys"
os.makedirs(CLIENT_KEYS_DIR, exist_ok=True)
icmp_reassembly_buffer = {}

### Pour rediriger des données UDP extraites vers une app
def forward_udp_to_application(udp_data, dest_ip='127.0.0.1', dest_port=12345):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
        udp_socket.sendto(udp_data, (dest_ip, dest_port))
        print(f"Données UDP envoyées à {dest_ip}:{dest_port} -> {udp_data}")

#######################################
### Fonctions Désencapsulation ICMP ###
#######################################

def extract_udp_from_icmp(packet):
    ip_header_length = 20
    icmp_header_length = 8
    udp_payload = packet[ip_header_length + icmp_header_length:]
    return udp_payload

def receive_icmp_packet(process_function=None):
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        s.bind(('0.0.0.0', 0))
        print("En attente de paquets ICMP...")

        while True:
            packet, addr = s.recvfrom(65535)
            print(f"Paquet ICMP reçu de {addr}")
            udp_data = extract_udp_from_icmp(packet)
            print(f"Données UDP extraites : {udp_data}")

            if not udp_data.startswith(b'KEY:'):
                print("[!] Trame ICMP ignorée : tag non reconnu")
                continue

            payload = udp_data[4:]
            try:
                client_public_key = payload.decode('utf-8').strip()
                print(f"Clé publique reçue : {client_public_key}")
                return client_public_key
            except UnicodeDecodeError:
                print("[!] Erreur de décodage de la clé publique")
                continue

            if process_function:
                process_function(udp_data)

def process_icmp_fragment(packet, udp_forward_ip='127.0.0.1', udp_forward_port=51820):
    udp_data = extract_udp_from_icmp(packet)
    if not udp_data.startswith(b'FRAG:'):
        print("[client] Trame ignorée (non fragmentée)")
        return

    try:
        header, data = udp_data.split(b':', 4)[:4], udp_data.split(b':', 4)[4]
        _, packet_id, index_str, total_str = [h.decode() for h in header]
        index, total = int(index_str), int(total_str)
    except Exception as e:
        print("[client] Erreur parsing header fragment:", e)
        return

    buffer = icmp_reassembly_buffer.setdefault(packet_id, {"total": total, "fragments": {}, "time": time.time()})
    buffer["fragments"][index] = data

    print(f"[client] Fragment {index+1}/{total} reçu pour ID {packet_id}")

    if len(buffer["fragments"]) == total:
        print(f"[client] Tous les fragments reçus pour ID {packet_id}, reconstruction...")
        full_data = b''.join(buffer["fragments"][i] for i in range(total))
        forward_udp_to_application(full_data, udp_forward_ip, udp_forward_port)
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
                return packet[28:]

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

### Fonction de fragmentation 
def send_large_udp_over_icmp(dest_ip, udp_data, mtu=1024):
    ### Découpe udp_data en fragments ICMP et les envoie avec un identifiant unique
    fragment_size = mtu
    total_fragments = (len(udp_data) + fragment_size - 1) // fragment_size
    packet_id = str(uuid.uuid4())[:8]

    for i in range(total_fragments):
        fragment = udp_data[i * fragment_size : (i + 1) * fragment_size]
        header = f"FRAG:{packet_id}:{i}:{total_fragments}:".encode()
        payload = header + fragment
        send_icmp_packet(dest_ip, payload)
        print(f"[client] Fragment {i+1}/{total_fragments} envoyé avec ID {packet_id}")

##########################################################
### Capture du trafic UDP WireGuard avant le firewall  ###
##########################################################

def monitor_udp_wireguard_traffic(interface, dest_ip, wg_port):
    print(f"[+] Surveillance de {interface} pour le trafic UDP WireGuard vers le port {wg_port}...")
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) as s:
        while True:
            packet = s.recvfrom(65535)[0]
            # Vérifie si c'est un paquet IPv4 (0x0800) et UDP
            eth_proto = struct.unpack('!H', packet[12:14])[0]
            if eth_proto != 0x0800:
                continue
            ip_proto = packet[23]
            if ip_proto != 17:  # UDP
                continue
            udp_segment = packet[34:]  # Ethernet(14) + IP(20)
            udp_dest_port = struct.unpack('!H', udp_segment[2:4])[0]
            if udp_dest_port == wg_port:
                print(f"[~] Paquet WireGuard intercepté sur {interface}, encapsulation ICMP...")
                send_large_udp_over_icmp(dest_ip, udp_segment)

def listen_icmp_fragments():
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        s.bind(('0.0.0.0', 0))
        print("[client] En attente de fragments ICMP...")
        while True:
            packet, _ = s.recvfrom(65535)
            process_icmp_fragment(packet)

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
    send_icmp_packet(server_ip, key_data, tag='KEY')

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
    

@app.route('/api/start_icmp_listener', methods=['GET'])
def start_icmp_listener():
    try:
        threading.Thread(target=listen_icmp_fragments, daemon=True).start()
        return jsonify({"success": True, "message": "Écoute ICMP fragments lancée"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
    
@app.route('/api/create_client_config', methods=['POST'])
def api_create_client_config():
    try:
        server_public_key = receive_icmp_packet()
        
        client_name = request.form.get('client_name')
        client_ip = request.form.get('client_ip')
        client_endpoint = request.form.get('client_endpoint')
        client_listen_port = request.form.get('client_listen_port')
        
        server_ip = request.form.get('server_ip')
        server_endpoint = request.form.get('server_endpoint')
        server_port = request.form.get('server_port')
        
        client_private_key = request.form.get('client_private_key')
        client_public_key = request.form.get('client_public_key')

        if not all([client_name, client_ip, server_ip, server_port, client_endpoint, server_endpoint, client_listen_port, client_private_key, client_public_key]):
            return jsonify({"success": False, "error": "Tous les champs sont requis"}), 400

        config_template = """[Interface]
PrivateKey = {{ client_private_key }}
SaveConfig = true
ListenPort = {{ client_listen_port }}
Address = {{ client_ip }}/24

[Peer]
PublicKey = {{ server_public_key }}
Endpoint = {{ server_endpoint }}:{{ server_port }}
AllowedIPs = {{ client_ip }}/32
"""
        config_content = render_template_string(
            config_template,
            client_private_key=client_private_key,
            client_ip=client_ip,
            server_port=server_port,
            client_listen_port=client_listen_port,
            server_endpoint=server_endpoint,
            server_public_key=server_public_key
        )

        config_path = os.path.join(WG_CONFIG_PATH, f"{WG_INTERFACE}.conf")

        with open(config_path, 'w') as config_file:
            config_file.write(config_content)

        return jsonify({"success": True, "message": "Configuration client créée avec succès", "file": config_path})
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/send_public_key', methods=["POST"])
def api_send_client_key():
    data = request.get_json()
    try:
        dest_ip = data.get("dest_ip")
    except:
        return jsonify({"success": False, "error": "Aucune adresse IP fournie"}), 400
    print(dest_ip)
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
        # Lance WireGuard
        subprocess.run(["wg-quick", "up", WG_INTERFACE], check=True)

        # Une fois le tunnel actif, lance l'encapsulation ICMP des paquets WireGuard
        # Tu peux ici choisir dynamiquement l'interface (ex: 'eth0') ou la mettre en dur
        interface = WG_INTERFACE
        wg_port = 51820
        threading.Thread(target=monitor_udp_wireguard_traffic, args=(interface, server_ip, wg_port), daemon=True).start()

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
