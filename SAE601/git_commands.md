# Glossaire des commandes GIT
git init - Initialise un nouveau dépôt Git dans le dossier actuel.
git clone <repository_url> - Clone un dépôt Git distant sur la machine locale.
git status - Affiche l’état actuel du dépôt, y compris les fichiers modifiés et non suivis.
git add <file> - Ajoute un fichier spécifique à l’index (staging area).
git add . - Ajoute tous les fichiers modifiés et non suivis à l’index.
git commit -m "Message du commit" - Crée un commit avec les modifications ajoutées à l’index.
git push origin <branch> - Envoie les commits locaux vers la branche distante spécifiée.
git pull origin <branch> - Récupère et fusionne les changements de la branche distante.
git branch - Liste les branches locales.
git checkout <branch> - Change de branche.
git checkout -b <new_branch> - Crée une nouvelle branche et bascule dessus.
git merge <branch> - Fusionne une branche dans la branche actuelle.
git log - Affiche l’historique des commits.
git reset --hard <commit_hash> - Réinitialise le dépôt à un commit spécifique, supprimant les modifications après celui-ci.
git stash - Sauvegarde temporairement les modifications en attente.
git stash pop - Récupère les modifications mises en attente avec `git stash`.
git rebase <branch> - Rebase la branche actuelle sur une autre branche.
git remote -v - Affiche les URLs des dépôts distants configurés.
git tag <tag_name> - Crée un tag sur un commit spécifique.
git fetch - Récupère les modifications distantes sans les fusionner.
