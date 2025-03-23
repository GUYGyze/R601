#!/bin/bash
sudo apt update && sudo apt install python3 python3-pip wireguard -y
chmod 777 bash/create_venv.sh
chmod 777 bash/requirements.sh
echo "Création de la venv en cours..."
./bash/create_venv.sh
sleep 3
echo "Activation de l'environnement virtuel..."
source sae_venv/bin/activate
sleep 3
echo "Télchargements des librairies en cours..."
./bash/requirements.sh
cd app
echo "Lancement de l'application..."
python3 app_server.py
