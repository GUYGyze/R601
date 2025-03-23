# Projet UDP over ICMP


## Contexte et objectif

- On veut traverser un pare-feu qui restreint l'usage d'UDP, soit totalement,
  soit sur les ports qui nous intéressent.
- On veut faire de l'UDP pour pouvoir monter un tunnel wireguard par dessus
- On ne veut pas encapsuler notre trafic dans TCP ou un protocole au dessus de
  TCP pour éviter le phénomène de "TCP Meltdown" (because wireguard: on veut
  pouvoir faire passer n'importe quoi dedans, notamment du TCP, SSH, etc)
- On suppose que le pare-feu laisser passer ICMP, ou a minima, ICMP request et
  ICMP reply (ping).
- On va coder un outil qui encapsule UDP dans ICMP à l'aide du payload ICMP.


## Contenu technique et contrainte

### Implémentation

On va tout coder nous-même, en Python (voire en C?). On pourra regarder comment
s'y prennent les outils existants (il existe un outil en go?), mais le but est
de faire notre propre outil.

On ne va pas utiliser Scapy. Raisons :
- ça va permettre de découvrir l'API réseau de linux
- ça va nous faire manipuler les octets des paquets à la main, et donc
  (re)découvrir les opérations bit à bit de Python

J'aimerais une « belle » interface : on ouvre le tunnel en lançant l'outil des
deux côté et on a moyen agréable de passer dedans : interface virtuelle sur
linux ?

Quelques aspects techniques à anticiper :
- tailles des paquets → fragmentation ?
- veut-on répondre aux pings ?
- quelle est l'api de linux pour créer des interfaces virtuelles ? (Et
  d'ailleurs, est-ce bien la bonne interface à utiliser pour nous ?)


### Phase expérimentale

On va faire des maquettes pour tester des choses.

1. Étape 1 : Je veux voir une maquette ultra simpliste avec un pare-feu ultra
   simpliste (par exemple nftables) qui bloque tout sauf ping. Vous devez
   réussir à traverser le pare feu.

2. Étape 2 : Je veux qu'on essaie avec un vrai pare-feu (Stormshield ?) et une
   config basique (niveau 4). J'aimerais qu'on regarde si on traverse

3. Étape 3 : Je veux qu'on essaie avec un vrai pare-feu (Stormshield ?) et une
   config plus fine. Est-ce qu'il nous bloque ? À cause de quoi ? Peut-on
   réussir à le berner ?

4. Étape 3 bis : Le réseau de l'université bloque la plupart des ports en UDP,
   notamment le 53. Est-ce qu'on arrive à traverser le pare-feu de l'université
   ? → Autorisation à demander au préalable à la DSI.

### Résumé des étapes :

1) Les deux machines ont accès à leur fichier de configuration WireGuard et aux scripts

    Chaque machine dispose d'un fichier de configuration WireGuard qui contient ses clés privées, la clé publique de l'autre machine, l'adresse IP du tunnel, et les autres informations nécessaires pour établir le tunnel.
    Chaque machine a aussi un script qui permet de capturer, encapsuler et envoyer des paquets UDP dans des paquets ICMP afin de contourner le pare-feu.

2) Le pare-feu entre les deux machines empêche la communication directe, sauf via les pings (ICMP)

    Le pare-feu est configuré de manière à bloquer le trafic UDP (utilisé normalement par WireGuard) entre les deux machines. Cependant, les paquets ICMP sont autorisés, ce qui permet de contourner cette restriction.

3) Les deux machines lancent le tunnel WireGuard

    Sur chaque machine, WireGuard est configuré et démarré à l'aide de la commande wg-quick up avec le fichier de configuration correspondant. Cela initie la création du tunnel sécurisé en utilisant UDP.
    Mais le pare-feu bloque ces paquets UDP, empêchant la négociation du tunnel.

4) Les trames sont envoyées et captées par les scripts, ce qui permet de les faire passer par le pare-feu

    Machine 1 : Dès que la machine 1 tente d'envoyer un paquet UDP pour démarrer la négociation du tunnel, le script de capture sur cette machine capture le paquet UDP, l'encapsule dans un paquet ICMP et le renvoie à la machine 2.
    Machine 2 : De manière similaire, le paquet ICMP contenant le paquet UDP est capté par le script de la machine 2, qui le désencapsule et renvoie le paquet UDP via WireGuard (comme si le pare-feu n'avait pas bloqué la communication initiale).

Cette technique permet de contourner le pare-feu, car les paquets ICMP sont souvent autorisés par défaut, tandis que les paquets UDP sont bloqués.
5) Un tunnel WireGuard est monté au-dessus du tunnel ICMP

  Une fois les paquets de montage du tunnel transmis avec succès entre les deux machines, le tunnel WireGuard est établi. Le trafic réel (données utilisateur) peut maintenant être acheminé à travers ce tunnel sécurisé.
  Les paquets peuvent ensuite circuler normalement sur le tunnel WireGuard, en utilisant UDP pour la communication, et non plus ICMP. Le pare-feu, qui bloque UDP, n'a plus d'impact, car le tunnel est désormais fonctionnel.

Conclusion

Avant que le tunnel soit établi, tu utilises l'encapsulation ICMP pour faire passer les trames de montage à travers le pare-feu.
Une fois le tunnel WireGuard établi, la communication peut se faire normalement, sans avoir à passer par l'encapsulation ICMP.

### Pistes d'amélioration

Si tout marche :
- ICMPv6 → vous force à rendre votre code assez générique pour ne pas tout
  recoder deux fois
- Optimiser les performances → où est le bottleneck ? Comment remédier ? Etc.


## Questions / réponses

- UDP over ICMP… Mais c'est n'importe quoi ? Oui, du coup c'est drôle
- UDP over ICMP… Mais pourquoi ? Un attaquant pourrait essayer de faire ça, alors nous aussi.
- Mais c'est sale non ? Oui
- Et pourquoi tout recoder à la main ? Pour apprendre des trucs au passage
- Et les perfs ? Probablement catastrophiques, on verra si on arrive à optimiser
- Pourquoi wireguard ? J'aime bien
