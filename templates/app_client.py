from flask import Flask, render_template, request, jsonify
import subprocess
import os

app = Flask(__name__)

# Chemin des fichiers de configuration WireGuard
WG_CONFIG_PATH = "/etc/wireguard/wg0.conf"
WG_INTERFACE = "wg0"
CLIENT_PRIVATE_KEY_PATH = "client_privatekey"
CLIENT_PUBLIC_KEY_PATH = "client_publickey"

os.makedirs(WG_CONFIG_PATH, exist_ok=True) # vérifier que le dossier de configuration existe

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
