from flask import Flask, render_template, request, jsonify
import subprocess
import os

app = Flask(__name__)

# Chemin des fichiers de configuration WireGuard
WG_CONFIG_PATH = "/etc/wireguard/wg0.conf"
WG_INTERFACE = "wg0"
SERVER_PRIVATE_KEY_PATH = "server_privatekey"
SERVER_PUBLIC_KEY_PATH = "server_publickey"

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
