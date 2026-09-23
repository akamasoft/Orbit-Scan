<div align="center">

# Orbite Scan
![Analyseur de trafic](ui/assets/logosite.png)

**Autour de la passerelle.**

![Python](https://img.shields.io/badge/Python-3.11+-00ff99?style=flat-square&logo=python&logoColor=black)
![Plateforme](https://img.shields.io/badge/Plateforme-Linux%20%7C%20Windows%20%7C%20macOS-00ff99?style=flat-square)
![Licence](https://img.shields.io/badge/Licence-GPL--v3-00ff99?style=flat-square)
![Statut](https://img.shields.io/badge/Statut-Développement%20actif-orange?style=flat-square)

Outil professionnel de supervision et de visualisation réseau, conçu pour les chercheurs en sécurité.

L’interface est en français par défaut.

https://github.com/user-attachments/assets/745eb888-0636-47e8-9293-38a706a8e897

</div>

---

## Qu’est-ce qu’Orbite Scan ?

Orbite Scan est un outil de supervision réseau de niveau professionnel qui associe la puissance de nmap à une interface sombre, claire et moderne. Il s’adresse aux chercheurs en sécurité et aux administrateurs réseau qui ont besoin d’une visibilité rapide et détaillée sur leur infrastructure.

Orbite Scan est l’outil de supervision réseau édité par Akamasoft. Le code est publié sur [github.com/akamasoft/Orbit-Scan](https://github.com/akamasoft/Orbit-Scan), sous la licence GNU GPL-3.0 ou ultérieure. Il comprend du code de L0p4Map, © HaxL0p4.

Pas de superflu. Pas de détour. Juste l’intelligence réseau, brute.

Disponible sur Linux, Windows et macOS.

---

## Fonctionnalités

- **Multiplateforme** : fonctionne sur Linux (Debian/Arch), Windows et macOS, avec la même interface et le même ensemble de fonctions
- **Surveillance continue** : agent léger qui observe passivement le trafic ARP et mDNS, sans devoir rescanner tout le réseau
- **Alertes** : notification en temps réel lorsqu’un nouvel appareil non autorisé apparaît sur le réseau
- **Interrogation SNMP continue** : requêtes SNMP périodiques pour maintenir l’état des appareils à jour, sans attendre le prochain cycle de scan
- **Scan réseau ARP** : découverte rapide des hôtes, avec recherche dans une base OUI IEEE locale
- **Cartographie de plages** : scan de n’importe quelle IP, d’un CIDR ou d’une plage. Les plages routées sont cartographiées par traceroute (hôtes regroupés sous leur dernier routeur)
- **Résolution des noms** : détection par DNS inverse, NetBIOS (Windows) et mDNS/Avahi (Linux, Mac, objets connectés)
- **Empreinte des appareils** : indice d’OS d’après le TTL (Linux/macOS, Windows, équipement réseau), sondage TCP des ports utiles à la topologie, requête SNMP brute `sysDescr` (sans bibliothèque externe)
- **Empreinte des services embarqués** : détection passive d’iLO, InfoPrint, XPort, SATO et Zebra par récupération de bannière, avec signalement sur le graphe des appareils connus pour être livrés avec des identifiants par défaut, à vérifier manuellement
- **Détection de rôle** : classification automatique de chaque hôte (passerelle, routeur, point d’accès, commutateur, PC, Apple, mobile, Raspberry Pi, machine virtuelle, inconnu) à partir du fabricant, du nom d’hôte, du TTL, des ports ouverts et de la réponse SNMP
- **Graphe de topologie réel** : graphe hiérarchique vis.js qui reflète la structure du réseau : passerelle en haut, équipements intermédiaires (routeurs, points d’accès, commutateurs) au deuxième niveau, clients regroupés sous leur parent. Bascule entre les dispositions Hiérarchique et Force Atlas
- **Cadres de sous-réseaux** : chaque sous-réseau détecté est dessiné en surimpression pointillée sur le graphe, avec son CIDR
- **Liens typés** : trois types de liens visuellement distincts : liaison montante (passerelle vers Internet), dorsale (équipement intermédiaire vers la passerelle), lien client (appareil vers son parent)
- **Panneau de topologie** : superposition en direct du sous-réseau, de l’IP de la passerelle, du nombre total d’appareils et du nombre d’équipements intermédiaires
- **Intégration nmap complète** : scan SYN, UDP, détection d’OS, version des services, scripts NSE
- **Récupération de bannières** : énumération HTTP, SMB, FTP, SSH et SSL
- **Détection de vulnérabilités** : recherche de CVE via les scripts vulners, vuln et malware
- **Surface d’attaque** : services exposés, ports ouverts et vue des CVE par hôte, avec score CVSS et lien direct vers la NVD ; export des résultats en CSV
- **Analyseur de trafic** : capture de paquets en temps réel, statistiques par appareil, couleurs par protocole, barre de filtre, double-clic pour lancer un scan de ports ; export CSV
- **Traceroute** : basé sur ICMP, avec sortie en temps réel
- **Choix de l’interface** : sélection de l’interface réseau à analyser
- **Suivi en direct** : rafraîchissement automatique du graphe à intervalle réglable (30 s / 60 s / 120 s)
- **Export du scan** : enregistrement de la sortie nmap complète dans un fichier `.txt`
- **Export du graphe** : export de la topologie en CSV ou PNG
- **Libellés personnalisés** : attribution d’un nom personnalisé à n’importe quel appareil directement sur le graphe (double-clic)
- **Interface sombre** : construite avec PyQt6, en français par défaut

---

## Captures d’écran

### Accueil : scanner réseau
![Accueil](img/lopamap1.png)

### Scan de ports : intégration nmap complète
![Scan de ports](img/lopamap2.png)

### Topologie réseau : graphe hiérarchique
![Graphe de topologie | Hiérarchique](img/retepng1.png)

### Topologie réseau : disposition Force Atlas
![Graphe de topologie | Force Atlas](img/retepng2.png)

### Surface d’attaque : services exposés, ports ouverts et vulnérabilités
![Section surface d’attaque](img/Ats.png)

### Analyseur de trafic : analyse du trafic en temps réel
![Analyseur de trafic](img/traffic2.png)

---

## Prérequis

### Linux (Fedora, Debian, Arch, openSUSE, Alpine, Void…)
- Python 3.11 ou plus
- nmap (le lanceur l’installe avec le gestionnaire du système : dnf, apt, pacman, zypper, apk, xbps…)
- Npcap/libpcap pour la capture de paquets (en général déjà présent, ou tiré par nmap)
- Privilèges root (requis pour le scan ARP et la capture de paquets)

### Windows 10/11
- Python 3.11 ou plus
- Nmap pour Windows (installateur officiel sur nmap.org, qui inclut Npcap)
- Npcap installé en mode compatible avec l’API WinPcap (requis pour la capture de paquets)
- Exécution en tant qu’administrateur (requis pour le scan ARP et la capture de paquets)

### macOS (Intel et Apple Silicon)
- Python 3.11 ou plus
- nmap installé (`brew install nmap`)
- Privilèges root (requis pour le scan ARP et la capture de paquets)

---

## Installation

### Linux

Installez Orbite Scan depuis [le dépôt Akamasoft](https://github.com/akamasoft/Orbit-Scan) :

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
chmod +x orbite-scan.sh
```

### macOS

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
chmod +x orbite-scan.sh
```

### Windows

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Vérifiez que nmap et Npcap sont installés et présents dans le PATH avant de lancer l’outil.

---

## Utilisation

### Linux et macOS

Lancez l’outil avec les privilèges root :

```bash
sudo ./orbite-scan.sh
```

### Windows

Ouvrez un terminal (PowerShell ou CMD) en tant qu’administrateur, puis :

```powershell
venv\Scripts\activate
python __main__.py
```

### Déroulement

1. Choisissez l’interface réseau dans la liste de la barre d’outils
2. Appuyez sur **Scanner** pour découvrir tous les appareils : chaque hôte est identifié via le TTL, le sondage des ports et SNMP
3. Cliquez sur un appareil pour voir le détail et lancer des actions rapides (ping, traceroute, scan de ports)
4. Passez au **Graphe** pour explorer la topologie réelle : survolez un nœud pour les informations complètes, double-cliquez pour lui donner un nom
5. Basculez entre **Hiérarchique** et **Force Atlas** depuis la vue graphe
6. Utilisez **Surface d’attaque** pour lancer un scan nmap + vulners approfondi sur un hôte et consulter les CVE
7. Utilisez **Analyse du trafic** pour capturer les paquets en direct, filtrer par appareil ou protocole, et exporter en CSV
8. Activez **Direct** dans la vue graphe pour maintenir la topologie à jour automatiquement
9. Activez **Continu** pour que l’agent écoute passivement ARP/mDNS et alerte sur les nouveaux appareils, sans relancer un scan complet

---

## Avertissement

Cet outil est conçu **uniquement pour l’audit de réseaux autorisés**. N’utilisez Orbite Scan que sur des réseaux qui vous appartiennent ou pour lesquels vous avez une autorisation explicite. Un scan non autorisé est illégal.

---

## Éditeur

**Akamasoft** : [github.com/akamasoft/Orbit-Scan](https://github.com/akamasoft/Orbit-Scan)

Licence GNU GPL-3.0 ou ultérieure. Comprend du code de L0p4Map, © HaxL0p4.
