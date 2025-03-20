from flask import Flask, render_template, request, jsonify
import subprocess
import os

app = Flask(__name__)

# Chemin des fichiers de configuration WireGuard
WG_CONFIG_PATH = "/etc/wireguard/wg0.conf"
WG_INTERFACE = "wg0"
SERVER_PRIVATE_KEY_PATH = "server_privatekey"
SERVER_PUBLIC_KEY_PATH = "server_publickey"

os.makedirs(WG_CONFIG_PATH, exist_ok=True) # vérifier que le dossier de configuration existe

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

@app.route('/api/create_client_config', methods=['POST'])
def api_create_client_config():
    try:
        # Récupération des données du formulaire
        client_name = request.form.get('client_name')
        client_ip = request.form.get('client_ip')
        server_endpoint = request.form.get('server_ip')
        server_port = request.form.get('server_port')
        private_key = request.form.get('client_private_key')
        public_key = request.form.get('client_public_key')

        # Vérifier que toutes les données sont bien fournies
        if not all([server_ip, server_listen_port, client_port, client_ip, server_ip, server_private_key, server_public_key]):
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


# Envoi de la clé publique via le script encap.py
# A changer
def send_server_key():
    subprocess.run(["python3", "encap.py", "server"])

# Routes Flask
@app.route('/server')
def server_index():
    # Afficher la page du serveur
    server_private_key, server_public_key = save_server_keys()
    return render_template('server/index_server.html', server_public_key=server_public_key)

@app.route('/api/generate_server_keys')
def api_generate_server_keys():
    # Générer et retourner les clés du serveur
    server_private_key, server_public_key = save_server_keys()
    return jsonify({"private_key": server_private_key, "public_key": server_public_key})

@app.route('/api/send_server_key', methods=["POST"])
def api_send_server_key():
    # Exécuter le script pour envoyer la clé publique du serveur
    send_server_key()
    return jsonify({"success": True, "message": "Clé publique envoyée au client"})

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
