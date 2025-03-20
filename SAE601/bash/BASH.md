# Etapes de réalisation (Root)
1) Donner les permissions pour tous les fichiers bash avec : chmod 777 <nom du fichier bash>
2) Executer le fichier create_venv.sh avec la commande ./create_venv.sh
3) Executer le fichier requirements.sh avec la commande ./requirements.sh
4) Executer le fichier create_docker.sh avec la commande ./create_docker.sh
5) Executer le fichier /app/app.py avec la commande python3 app.py
6) Rendez vous sur un navigateur web et allez sur http:172.0.0.1:5000



# Documentation Conteneur

## Supression des conteneurs si shutdown
docker rm <nom_du_conteneur>  ou docker rm <ID_du_conteneur>

## Forcer la supression des conteneurs non shutdown
docker rm -f <nom_du_conteneur>

## Supression de tous les conteneurs si shutdown
docker container prune -f

## Supression de tous les conteneurs non shutdown
docker rm -f $(docker ps -aq)

## Lister tous les ID des conteneurs existants
docker ps -aq

