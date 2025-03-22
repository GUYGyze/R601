#!/bin/bash
chmod 777 bash/create_venv.sh
chmod 777 bash/requirements.sh
./bash/create_venv.sh

sleep 5

source sae_venv/bin/activate
./bash/requirements.sh
