# 🛡️ SecuWatch API

**Moteur d'audit de cybersécurité et de vulnérabilités web.**

Ce projet constitue le Backend de la plateforme SecuWatch. Il s'agit d'une API REST performante conçue pour automatiser la reconnaissance et l'analyse de sécurité des sites web.

🚀 **Documentation Swagger (Live) :** [https://secuwatch-api.onrender.com/docs](https://secuwatch-api.onrender.com/docs)

## ⚡ Fonctionnalités Techniques

### 🔐 Sécurité & Authentification
* **Authentification JWT :** Système complet de protection des routes via JSON Web Tokens.
* **Hachage de Mots de Passe :** Utilisation de **Bcrypt** (via Passlib) pour le stockage sécurisé.
* **Gestion des Secrets :** Configuration via variables d'environnement (`.env`).

### 🕵️‍♂️ Moteur de Scan
* **Analyse SSL/TLS :** Vérification bas niveau (`socket`) de la validité et de la chaîne de certification.
* **Scan de Ports (TCP) :** Détection des services exposés (FTP, SSH, SQL...) via sockets bruts.
* **Conformité OWASP :** Audit des en-têtes de sécurité HTTP (HSTS, CSP, X-Frame-Options).
* **OSINT :** Recherche de fichiers sensibles (`security.txt`).

### 📊 Reporting & Data
* **Génération PDF :** Création dynamique de rapports d'audit détaillés.
* **Historique Persistant :** Base de données relationnelle (SQLAlchemy) liant chaque scan à son utilisateur.

## 🛠️ Stack Technique

* **Langage :** Python 3.10+
* **Framework :** FastAPI
* **Sécurité :** OAuth2, Python-Jose, Bcrypt
* **Base de Données :** SQLite (Dev) / PostgreSQL (Prod)
* **Déploiement :** Render Cloud

## ⚙️ Installation Local

1.  **Cloner le projet**
    ```bash
    git clone [https://github.com/AdamRchd/secuwatch-api.git](https://github.com/TON-PSEUDO/secuwatch-api.git)
    cd secuwatch-api
    ```

2.  **Configurer l'environnement**
    Créez un fichier `.env` à la racine et ajoutez votre clé secrète :
    ```text
    SECRET_KEY=votre_cle_tres_secrete_ici
    ```

3.  **Installer les dépendances**
    ```bash
    python -m venv env
    source env/bin/activate  # ou .\env\Scripts\activate sur Windows
    pip install -r requirements.txt
    ```

4.  **Lancer le serveur**
    ```bash
    uvicorn main:app --reload
    ```

## 👤 Auteur
**[Adam] [Rached]** - *Projet d'étude en Cybersécurité*
