# 🛡️ Hemerson TrustLink v5.0
### Détection Intelligente de Fraude Financière
> Machine Learning • IA • Temps Réel

**Auteur :** Anoh Amon Francklin Hemerson  
**Superviseur :** M. AKPOSSO DIDIER MARTIAL  
**Institution :** INSSEDS  
**© 2026 - Premium**



## 📋 Description

**Hemerson TrustLink** est une application web de détection de fraude financière en temps réel, développée avec Streamlit et des modèles de Machine Learning avancés. Elle analyse 30 caractéristiques de transaction pour évaluer le risque de fraude avec un score IA certifié.



## ✨ Fonctionnalités v5.0

| Fonctionnalité | Description |
|---|---|
| 🔐 Authentification sécurisée | Google OAuth 2.0 + accès admin PBKDF2-SHA256 |
| 🤖 Analyse IA temps réel | Score de fraude sur 30 variables (V1-V28 + montant + temps) |
| 📊 Analyse en lot | Import CSV avec détection batch et export résultats |
| 📄 Export PDF | Rapport professionnel généré automatiquement |
| 🔊 Alertes sonores | Notification audio en cas de fraude détectée |
| 🗺️ Carte géographique | Carte de risque régionale — Côte d'Ivoire |
| 📈 Score santé portefeuille | Notation A/B/C/D du portefeuille de transactions |
| 💰 Estimation pertes évitées | Calcul automatique des pertes évitées par détection |
| ⚙️ Seuils personnalisables | Ajustement des seuils de détection selon le contexte |
| 🚨 Transactions critiques | Marquage et suivi des transactions à haut risque |
| 📝 Notes analyste | Annotation manuelle des transactions analysées |
| 🎉 Confetti zéro fraude | Animation si 0 fraude détectée sur 10+ transactions |
| ⏰ Horloge temps réel | Horloge en direct dans la sidebar |
| 💡 Tooltips V1-V28 | Explication IA de chaque variable du modèle |

---


## ⚙️ Installation locale

### Prérequis
- Python 3.10+
- pip

### Étapes

```bash
# 1. Cloner le dépôt
git clone https://github.com/emeroson/hemerson-app.git
cd hemerson-app

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Configurer les secrets
mkdir .streamlit
cp .streamlit/secrets.toml.example .streamlit/secrets.toml
# Remplir les valeurs dans .streamlit/secrets.toml

# 4. Lancer l'application
streamlit run app.py
```

---

## 🔐 Configuration des secrets

Créer le fichier `.streamlit/secrets.toml` :

```toml
GOOGLE_CLIENT_ID     = "xxx.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "GOCSPX-xxx"
REDIRECT_URI         = "https://hemerson-trustlink.streamlit.app/~/+/oauth2callback"
BASE_URL             = "https://hemerson-trustlink.streamlit.app"
ADMIN_PASSWORD       = "VotreMotDePasseAdmin"
```

> ⚠️ Ne jamais committer ce fichier. Il est dans `.gitignore`.

---

## 📦 Dépendances principales

```
streamlit
scikit-learn
pandas
numpy
plotly
joblib
google-auth-oauthlib
google-auth
requests
```

---

## 🏗️ Architecture

```
hemerson-app/
│
├── app.py              # Application principale
├── model.pkl           # Modèle ML entraîné
├── scaler.pkl          # Scaler des données
├── requirements.txt    # Dépendances Python
├── README.md           # Ce fichier
└── .streamlit/
    └── secrets.toml    # Secrets (non versionné)
```

---

## 🔒 Sécurité

- **Google OAuth 2.0** — authentification via compte Gmail
- **PBKDF2-HMAC-SHA256** — mot de passe admin hashé (310 000 itérations)
- **Anti-brute-force** — verrouillage 5 min après 5 échecs
- **Expiration de session** — déconnexion automatique après 30 min d'inactivité
- **Whitelist email** — restriction optionnelle aux emails autorisés

---

## 📊 Modèle ML

Le modèle est entraîné sur le dataset **Credit Card Fraud Detection** et analyse :
- **28 variables anonymisées** (V1 à V28) issues d'une ACP
- **Montant** de la transaction
- **Temps** écoulé depuis la première transaction

---

## application 

lien de l'application:https://hemerson-trustlink.streamlit.app/~/+/oauth2callback



*© 2026 INSSEDS — Hemerson TrustLink v5.0*
