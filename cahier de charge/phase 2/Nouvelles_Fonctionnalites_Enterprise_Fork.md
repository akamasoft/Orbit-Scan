# DOCUMENT DE SPÉCIFICATIONS TECHNIQUES ET FONCTIONNELLES
## EXTENSION DES FONCTIONNALITÉS POUR ORBITE SCAN (NIVEAU ENTREPRISE / NESSUS-LIKE)

### 1. SYNTHÈSE DE LA VISION PRODUIT
Pour faire d'Orbite Scan, édité par Akamasoft, une solution de gestion des vulnérabilités de classe entreprise capable de concurrencer les leaders du marché (Nessus, Qualys, Rapid7), l'outil doit dépasser le simple scan de réseau périphérique. L'objectif est d'implémenter des capacités d'analyse interne, de conformité réglementaire, d'évaluation dynamique du risque et d'intégration écosystémique. 

Ce document détaille les spécifications des 6 nouveaux modules stratégiques indispensables pour positionner cette nouvelle solution sur le marché B2B.

---

### 2. DÉTAIL DES NOUVELLES FONCTIONNALITÉS "ENTREPRISE"

#### 🛑 MODULE 1 : Scans Authentifiés & Analyse en Profondeur (Credentialed Scans)
*   **Description :** Permet à l'application de se connecter directement aux machines cibles à l'aide d'identifiants sécurisés pour inspecter le système d'exploitation de l'intérieur.
*   **Spécifications Techniques :**
    *   **Protocoles supportés :** SSH (avec clés privées/mots de passe) pour les environnements Linux/Unix, et SMB/WMI (avec intégration Active Directory) pour les environnements Windows.
    *   **Gestion du Trousseau (Credentials Vault) :** Chiffrement au repos des identifiants stockés dans la base SQLite locale via l'algorithme AES-256.
    *   **Actions exécutées :** 
        *   Requête directe du registre Windows et des gestionnaires de paquets (APT, YUM, DNF, Pacman).
        *   Comparaison de la liste des logiciels et des versions des DLL/binaires avec le référentiel des vulnérabilités.
        *   Vérification de l'état des correctifs de sécurité (ex: détection des KB Windows manquants).

#### 🛡️ MODULE 2 : Flux de Mises à Jour & Moteur de Plugins Propriétaire (Threat Intelligence Feed)
*   **Description :** Transition d'une dépendance stricte aux scripts Nmap (NSE) vers un moteur de détection exclusif et dynamique alimenté par abonnement.
*   **Spécifications Techniques :**
    *   **Moteur d'exécution :** Création d'un interpréteur de micro-plugins écrits en Python natif ou en Lua, standardisés pour tester des vulnérabilités spécifiques (ex: requêtes HTTP ciblées pour tester une faille Zero-Day).
    *   **Threat Intelligence Feed :** Système de synchronisation automatisé via HTTPS. L'application interroge un serveur distant sécurisé toutes les 24 heures pour télécharger les nouvelles signatures de vulnérabilités.
    *   **Modèle Commercial :** Ce flux constitue le cœur du modèle d'abonnement récurrent (SaaS/Licence annuelle).

#### 📜 MODULE 3 : Audit de Configuration & Conformité (Hardening & Compliance)
*   **Description :** Module permettant de vérifier si la configuration des systèmes respecte les politiques de sécurité internes et les réglementations internationales.
*   **Spécifications Techniques :**
    *   **Référentiels intégrés :** Intégration des modèles d'audit basés sur les standards du CIS (Center for Internet Security), ainsi que des matrices de conformité RGPD, ISO 27001 et PCI-DSS.
    *   **Mécanisme d'évaluation :** Analyse des fichiers de configuration critiques (ex: `/etc/ssh/sshd_config`, politiques de groupe Windows GPO).
    *   **Indicateurs clés :** Détection de l'utilisation de protocoles obsolètes (TLS 1.0, SSL v3, SMBv1), validation de la politique de complexité des mots de passe, et vérification de l'activation des pare-feux locaux.

#### 📈 MODULE 4 : Moteur de Priorisation Dynamique du Risque (VPR / Scoring Avancé)
*   **Description :** Algorithme intelligent permettant de trier et de hiérarchiser des milliers de vulnérabilités pour éviter la fatigue des alertes chez les administrateurs.
*   **Spécifications Techniques :**
    *   **Score Statique vs Dynamique :** Combinaison du score théorique de la faille (CVSS v3/v4 Base Score) avec des données contextuelles du marché de la menace (Temporal/Environmental Scores).
    *   **Flux d'Exploitation :** Corrélation automatique avec les bases d'exploits publics (Metasploit, Exploit-DB, CISA KEV - Known Exploited Vulnerabilities).
    *   **Règle de Priorisation :** Une vulnérabilité avec un score CVSS de 7.5 activement exploitée dans la nature (présente dans le catalogue CISA) sera classée comme *plus critique* qu'une faille à 9.0 ne disposant d'aucun exploit fonctionnel connu.

#### ⚡ MODULE 5 : Agents de Scan Légers Déportés (Agent-Based Scanning)
*   **Description :** Composant logiciel installé localement sur les endpoints pour auditer les machines sans saturer le réseau et couvrir le personnel en télétravail.
*   **Spécifications Techniques :**
    *   **Architecture :** Agent ultra-léger compilé statiquement (en Go ou Rust) pour n'avoir aucune dépendance logicielle locale. Consommation CPU bridée à 5% maximum.
    *   **Communication :** L'agent initie une connexion sortante unique via HTTPS (Port 443) vers l'API centrale (Architecture Headless). Il télécharge ses instructions, exécute le scan en local, et renvoie le rapport chiffré.
    *   **Avantage concurrentiel :** Permet d'auditer des machines situées derrière des pare-feux stricts ou des connexions domestiques instables sans nécessiter d'ouverture de ports entrants.

#### 🔌 MODULE 6 : Connecteurs d'Intégration Cyber (SIEM, SOAR & Ticketing)
*   **Description :** Permet à la plateforme de s'insérer nativement dans l'écosystème de sécurité préexistant des grandes entreprises.
*   **Spécifications Techniques :**
    *   **Export SIEM/Log Management :** Connecteurs natifs pour l'expédition en temps réel des vulnérabilités découvertes vers Splunk, la suite Elastic (ELK) ou Datadog au format JSON standardisé ou Syslog CEF.
    *   **Intégration Ticketing (Remédiation) :** Liaison avec l'API de Jira Service Management et ServiceNow. Possibilité de configurer une règle : *"Si une faille critique avec exploit public est détectée sur un serveur de production, créer automatiquement un ticket de remédiation Urgent attribué à l'équipe SysAdmin"*.

---

### 3. IMPACT SUR L'ARCHITECTURE DU FORK
L'ajout de ces fonctionnalités transforme l'architecture logicielle initiale :
1.  **Couche d'abstraction des scans :** Le moteur ne se contente plus d'appeler le binaire Nmap local. Il orchestre un pipeline composé de Nmap (scan réseau), du gestionnaire SSH/SMB (scan authentifié), et de l'interpréteur de plugins internes.
2.  **Base de données centralisée (SQLite/PostgreSQL) :** Stockage des identifiants (chiffrés), de l'historique temporel des scans pour le calcul différentiel, et des métadonnées de priorisation du risque.
3.  **Déploiement Hybride :** La console de gestion (UI) peut être hébergée localement ou dans le cloud, tandis que les modules de scan s'exécutent au plus près du réseau via des démons ou des agents.

---
*Ce document sert de spécification de référence pour l'équipe de développement et le cadrage du modèle commercial.*
