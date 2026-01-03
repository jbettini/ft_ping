# Def

* **FQDN (Fully Qualified Domain Name)** : Nom de domaine complet (ex: `google.com`) que tu dois traduire en IP via le DNS.
* **ICMP (Internet Control Message Protocol)** : Protocole de maintenance du réseau utilisé par Ping (Echo) et Traceroute (Erreurs).
* **TTL (Time To Live)** : Compteur dans le paquet IP qui diminue de 1 à chaque routeur ; à 0, le paquet est détruit.
* **RTT (Round-Trip Time)** : Temps écoulé (en ms) entre l'envoi de ta requête et la réception de la réponse.
* **Raw Socket** : Socket "manuel" qui te permet d'écrire toi-même les en-têtes (Headers) du paquet au lieu de laisser faire le système.
* **Checksum** : Somme mathématique de validation ; si tu te trompes dans ce calcul, le destinataire jette ton paquet.
* **DNS (Domain Name System)** : L'annuaire qui transforme un nom (FQDN) en adresse IP (utilisé par `getaddrinfo`).
* **Big Endian (Network Byte Order)** : Ordre de lecture des octets sur le réseau (inverse de ton PC Intel) ; utilise `htons()` pour convertir.

# TODO

[x] Parsing des argument avec getops
    [x] *-v* flag verbose se baser sur l'output de inetutils2.0                 No arg
    [x] *-?* affiche le help                                                    No arg    
    [x] *-c* flag count qui stop apres N ping                                   Arg
    [x] *-ttl* flag set time to live, mandatory pour traceroute                 Arg
    [x] *-i* flag interval, change le temps entre deux ping                     Arg
    [x] *-f* flag flood, spam de ping sans attendre                             No arg
    [ ] *-W* flag Timeout, Customize le timeout de recvfrom                     No arg


[x] Main function and logic
    [x] DNS (getaddrinfo) : Transformer "google.com" en IP
    [x] Raw Sockets : Créer le socket, gérer les permissions root  
    [x] ICMP Protocol : Construire les paquets à la main (Header, Data, Sequence, ID)  
        [x] Envoie
        [x] Reception
    [x] Checksum : L'algorithme de vérification (bit à bit)
    [x] Signal Handler : Gérer le Ctrl+C proprement pour afficher les stats à la fin 
    [x] Timing : Calculer le RTT (Round Trip Time) avec précision


[ ] Bonus
    [x] *-c* flag count qui stop apres N ping
    [x] *-i* flag interval, change le temps entre deux ping
    [x] *-f* flag flood, spam de ping sans attendre
    [ ] *-W* flag Timeout, Customize le timeout de recvfrom                     No arg
    [ ] *-ttl* flag set time to live, mandatory pour traceroute                 Arg
    [ ] Adapter *-v* pour chaque flags bonus
    [ ] Gerer de nouveau icmpreply types pour les flags en *-W* et -ttl*


https://ekman.cx/articles/icmp_sockets/

-   pas de route reseau 
ip route del default 

-   paquet qui revient avec l'erreur icmp-unreachable
iptables -A OUTPUT -d 8.8.8.8 -j REJECT --reject-with icmp-net-unreachable