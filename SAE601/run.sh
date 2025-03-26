#!/bin/bash
sudo apt update && sudo apt install python3 python3-pip
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
echo 1 pour client et 2 pour serveur
read choice
if [ choice == 1 ]
then
    python3 app_client.py
else
    python3 app_server.py
fi
