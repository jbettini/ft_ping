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
    [x] *-n* flag Numeric only, affiche que les adresses IP sans reverse DNS    No arg


[ ] Main function and logic
    [x] DNS (getaddrinfo) : Transformer "google.com" en IP
    [x] Raw Sockets : Créer le socket, gérer les permissions root  
    [ ] ICMP Protocol : Construire les paquets à la main (Header, Data, Sequence, ID)  
    [ ] Checksum : L'algorithme de vérification (bit à bit)
    [ ] Signal Handler : Gérer le Ctrl+C proprement pour afficher les stats à la fin 
    [ ] Timing : Calculer le RTT (Round Trip Time) avec précision


https://ekman.cx/articles/icmp_sockets/