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
