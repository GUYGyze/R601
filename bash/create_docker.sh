#!/bin/bash

###################

#Dossier Courant
cd /home/adminetu/SAE601

# Création de l'arborescence
mkdir -p config
mkdir -p client_configs

##############################"

# Création des requirements
cd app
cat > requirements.txt << 'EOF'
flask==2.2.3
jinja2==3.1.2
EOF

########################################

#Création du fichier Dockerfile
cd /home/adminetu/SAE601/
cat > Dockerfile << 'EOF'
FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "app.py"]
EOF

#############################

# Création du fichier docker-compose.yml
cd /home/adminetu/SAE601
cat > docker-compose.yml << 'EOF'
version: '3'

services:
  wireguard:
    image: linuxserver/wireguard
    container_name: wireguard
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=Europe/Paris
      - SERVERURL=auto
      - SERVERPORT=51820
      - PEERS=1
      - PEERDNS=auto
      - INTERNAL_SUBNET=10.0.0.0/24
    volumes:
      - ./config:/config
      - /lib/modules:/lib/modules
    ports:
      - "51820:51820/udp"
    restart: unless-stopped
    sysctls:
      - net.ipv4.conf.all.src_valid_mark=1
    
  web-interface:
    image: python:3.10-slim
    container_name: wireguard-web
    volumes:
      - ./app:/app
      - ./config:/config:ro
      - ./client_configs:/app/client_configs
    working_dir: /app
    command: bash -c "pip install flask jinja2 && python app.py"
    ports:
      - "8080:5000"
    restart: unless-stopped
    depends_on:
      - wireguard
EOF

#############################

cd /home/adminetu/SAE601/
docker-compose up -d
