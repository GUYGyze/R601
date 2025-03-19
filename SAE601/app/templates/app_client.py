from flask import Flask, render_template, request, jsonify
import subprocess
import os

app = Flask(__name__)

# Chemin des fichiers de configuration WireGuard
WG_CONFIG_PATH = "/etc/wireguard/wg0.conf"
WG_INTERFACE = "wg0"
CLIENT_PRIVATE_KEY_PATH = "client_privatekey"
CLIENT_PUBLIC_KEY_PATH = "client_publickey"

# Génération des clés publiques et privées
def generate_keys():
    private_key = subprocess.check_output("wg genkey", shell=True).decode('utf-8').strip()
    public_key = subprocess.check_output(f"echo '{private_key}' | wg pubkey", shell=True).decode('utf-8').strip()
    return private_key, public_key

# Sauvegarde des clés publiques et privées du client
def save_client_keys():
    private_key, public_key = generate_keys()
    with open(CLIENT_PRIVATE_KEY_PATH, 'w') as f:
        f.write(private_key)
    with open(CLIENT_PUBLIC_KEY_PATH, 'w') as f:
        f.write(public_key)
    return private_key, public_key

# Envoi de la clé publique via le script encap.py
def send_client_key():
    subprocess.run(["python3", "encap.py", "client"])

# Routes Flask
@app.route('/client')
def client_index():
    # Afficher la page du client
    client_private_key, client_public_key = save_client_keys()
    return render_template('client/index_client.html', client_public_key=client_public_key)

@app.route('/api/generate_client_keys')
def api_generate_client_keys():
    # Générer et retourner les clés du client
    client_private_key, client_public_key = save_client_keys()
    return jsonify({"private_key": client_private_key, "public_key": client_public_key})

@app.route('/api/send_client_key', methods=["POST"])
def api_send_client_key():
    # Exécuter le script pour envoyer la clé publique du client
    send_client_key()
    return jsonify({"success": True, "message": "Clé publique envoyée au serveur"})

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5001)
