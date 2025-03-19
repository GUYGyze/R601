#############################

from flask import Flask, render_template, request, jsonify, redirect, url_for
import subprocess
import os
import jinja2
import json

app = Flask(__name__)

# Configuration
WG_CONFIG_PATH = "/etc/wireguard/wg0.conf"
WG_CONFIG_DIR = "/etc/wireguard"
WG_INTERFACE = "wg0"
SERVER_IP = "10.0.0.1/24"
SERVER_PORT = 51820
CLIENT_BASE_IP = "10.0.0."

# Modèle Jinja2 pour la configuration du serveur
SERVER_CONFIG_TEMPLATE = """
[Interface]
PrivateKey = {{ server_private_key }}
Address = {{ server_ip }}
ListenPort = {{ server_port }}
SaveConfig = true

{% for client in clients %}
[Peer]
PublicKey = {{ client.public_key }}
AllowedIPs = {{ client.ip }}/32
{% endfor %}
"""

# Modèle Jinja2 pour la configuration du client
CLIENT_CONFIG_TEMPLATE = """
[Interface]
PrivateKey = {{ client_private_key }}
Address = {{ client_ip }}/24
DNS = 8.8.8.8, 1.1.1.1

[Peer]
PublicKey = {{ server_public_key }}
Endpoint = {{ server_endpoint }}:{{ server_port }}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""

# Fonction pour générer une clé privée et publique
def generate_keys():
    private_key = subprocess.check_output("wg genkey", shell=True).decode('utf-8').strip()
    public_key = subprocess.check_output(f"echo '{private_key}' | wg pubkey", shell=True).decode('utf-8').strip()
    return private_key, public_key

# Fonction pour récupérer l'état de WireGuard
def get_wireguard_status():
    try:
        status = subprocess.check_output(f"wg show {WG_INTERFACE}", shell=True).decode('utf-8')
        return status
    except subprocess.CalledProcessError:
        return "Interface WireGuard non active"

# Fonction pour sauvegarder la configuration du client
def save_client_config(client_name, client_config):
    os.makedirs("client_configs", exist_ok=True)
    with open(f"client_configs/{client_name}.conf", "w") as f:
        f.write(client_config)

# Fonction pour charger la liste des clients
def load_clients():
    try:
        with open("clients.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return []

# Fonction pour sauvegarder la liste des clients
def save_clients(clients):
    with open("clients.json", "w") as f:
        json.dump(clients, f, indent=2)

# Fonction pour mettre à jour la configuration WireGuard du serveur
def update_wg_config():
    private_key, public_key = generate_keys()

    peers = load_clients()  # Peers sont les clients existants

    config_content = render_template("wg0.conf.j2", private_key=private_key, peers=peers)

    with open(WG_CONFIG_PATH, "w") as f:
        f.write(config_content)

    return private_key, public_key

# Fonction pour démarrer WireGuard
def start_wireguard():
    os.system("sudo systemctl restart wg-quick@wg0")

# Fonction pour mettre à jour la configuration du serveur
def update_server_config(clients):
    server_private_key = ""
    try:
        with open("server_privatekey", "r") as f:
            server_private_key = f.read().strip()
    except FileNotFoundError:
        server_private_key, _ = generate_keys()
        with open("server_privatekey", "w") as f:
            f.write(server_private_key)

    template = jinja2.Template(SERVER_CONFIG_TEMPLATE)
    server_config = template.render(
        server_private_key=server_private_key,
        server_ip=SERVER_IP,
        server_port=SERVER_PORT,
        clients=clients
    )

    with open(f"{WG_CONFIG_DIR}/{WG_INTERFACE}.conf", "w") as f:
        f.write(server_config)

# Routes

@app.route('/')
def index():
    """Page principale"""
    status = get_wireguard_status()
    clients = load_clients()
    return render_template('index.html', status=status, clients=clients)

@app.route('/monter', methods=["POST"])
def monter_tunnel():
    """Monter le tunnel WireGuard"""
    update_wg_config()
    start_wireguard()
    return redirect(url_for("index"))

@app.route('/api/status')
def api_status():
    """API pour récupérer l'état du tunnel"""
    status = get_wireguard_status()
    return jsonify({"status": status})

@app.route('/api/create_client', methods=['POST'])
def create_client():
    """API pour créer un nouveau client"""
    client_name = request.form.get('client_name')
    
    clients = load_clients()
    
    for client in clients:
        if client['name'] == client_name:
            return jsonify({"error": "Ce nom de client existe déjà"}), 400
    
    client_private_key, client_public_key = generate_keys()
    client_id = len(clients) + 2
    client_ip = f"{CLIENT_BASE_IP}{client_id}"
    
    client = {
        "name": client_name,
        "public_key": client_public_key,
        "private_key": client_private_key,
        "ip": client_ip
    }
    
    clients.append(client)
    save_clients(clients)
    
    server_public_key = subprocess.check_output("cat server_publickey", shell=True).decode('utf-8').strip()
    server_endpoint = request.form.get('server_endpoint', request.host.split(':')[0])
    
    template = jinja2.Template(CLIENT_CONFIG_TEMPLATE)
    client_config = template.render(
        client_private_key=client_private_key,
        client_ip=client_ip,
        server_public_key=server_public_key,
        server_endpoint=server_endpoint,
        server_port=SERVER_PORT
    )
    
    save_client_config(client_name, client_config)
    
    update_server_config(clients)
    subprocess.run(f"systemctl restart wg-quick@{WG_INTERFACE}", shell=True)
    
    return jsonify({
        "success": True,
        "client": {
            "name": client_name,
            "config": client_config
        }
    })

@app.route('/api/toggle_wireguard', methods=['POST'])
def toggle_wireguard():
    """API pour activer/désactiver le tunnel WireGuard"""
    action = request.form.get('action', 'up')
    
    if action not in ['up', 'down']:
        return jsonify({"error": "Action invalide"}), 400
    
    try:
        subprocess.run(f"wg-quick {action} {WG_INTERFACE}", shell=True, check=True)
        return jsonify({"success": True, "status": get_wireguard_status()})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/download_config/<client_name>')
def download_config(client_name):
    """API pour télécharger la configuration d'un client"""
    try:
        with open(f"client_configs/{client_name}.conf", "r") as f:
            config = f.read()
        return config, 200, {'Content-Type': 'text/plain', 'Content-Disposition': f'attachment; filename="{client_name}.conf"'}
    except FileNotFoundError:
        return jsonify({"error": "Configuration non trouvée"}), 404

if __name__ == '__main__':
    if not os.path.exists("server_privatekey") or not os.path.exists("server_publickey"):
        server_private_key, server_public_key = generate_keys()
        with open("server_privatekey", "w") as f:
            f.write(server_private_key)
        with open("server_publickey", "w") as f:
            f.write(server_public_key)
    
    os.makedirs(WG_CONFIG_DIR, exist_ok=True)
    update_server_config(load_clients())
    
    app.run(host='0.0.0.0', port=5000, debug=True)
