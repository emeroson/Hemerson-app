"""
╔═════════════════════════════════════════════════════════════════════════════════╗
║                                                                                 ║
║                  🛡️  HEMERSON TRUSTLINK v5.0  🛡️                             ║
║                                                                                 ║
║              DÉTECTION INTELLIGENTE DE FRAUDE FINANCIÈRE                       ║
║                     Machine Learning • IA • Temps Réel                         ║
║                                                                                 ║
║                   Auteur: Anoh Amon Francklin Hemerson                         ║
║                              © 2026 - Premium                                  ║
║                                                                                 ║
╚═════════════════════════════════════════════════════════════════════════════════╝

NOUVEAUTÉS v5.0:
- Page de connexion sécurisée
- Export PDF professionnel
- Alertes sonores fraude
- Analyse en lot (Batch CSV)
- Explication IA des variables
- Carte de risque géographique Côte d'Ivoire
- Horloge temps réel dans sidebar
- Seuils personnalisables
- Marquer transaction critique
- Notes analyste
- Score santé portefeuille (A/B/C/D)
- Estimation pertes évitées
- Confetti si 0 fraude sur 10+ transactions
- Tooltips V1-V28
- Version v5.0 visible
"""

import os
from dotenv import load_dotenv
load_dotenv(override=True)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# ── BASE_URL ngrok — doit pointer vers l'URL publique exposée par ngrok
# Définir dans .env :  BASE_URL=https://xxxx-xx-xx-xx-xx.ngrok-free.app
BASE_URL = os.getenv("BASE_URL")
import streamlit as st
import streamlit.components.v1 as components
import joblib
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
import time
import io
import base64

# ═════════════════════════════════════════════════════════════════════════════════
# ⚙️  CONFIGURATION PAGE
# ═════════════════════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="🛡️ Hemerson TrustLink - Détection Fraude IA Premium",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={"About": "🛡️ Hemerson TrustLink v5.0 - Auteur: Anoh Amon Francklin Hemerson"}
)

# ═════════════════════════════════════════════════════════════════════════════════
# 🔐 AUTHENTIFICATION SÉCURISÉE — HEMERSON TRUSTLINK v5.0
#
#   ARCHITECTURE :
#   ┌─────────────────────────────────────────────────────────────┐
#   │  VOIE A — Google OAuth 2.0 (utilisateurs normaux)           │
#   │    1. Clic bouton → redirection accounts.google.com         │
#   │    2. Google renvoie sur ?code=...&state=...                 │
#   │    3. fetch_token(authorization_response=URL_COMPLETE)       │
#   │    4. id_token JWT vérifié cryptographiquement               │
#   │    5. Email + nom + photo → session_state                    │
#   │                                                             │
#   │  VOIE B — Admin local (PBKDF2-HMAC-SHA256)                  │
#   │    • 1 seul compte autorisé : sonioff09@gmail.com         │
#   │    • Mot de passe hashé, comparaison timing-safe            │
#   │    • Champ email masqué (placeholder générique)             │
#   │                                                             │
#   │  SÉCURITÉ COMMUNE                                           │
#   │    • Anti-brute-force : verrou 5 min après 5 échecs         │
#   │    • Déconnexion : purge complète du session_state          │
#   └─────────────────────────────────────────────────────────────┘
# ═════════════════════════════════════════════════════════════════════════════════
import hashlib, os, hmac
import time as _time

# ── Dépendances Google OAuth ─────────────────────────────────────────────────
try:
    from google_auth_oauthlib.flow import Flow
    from google.oauth2 import id_token as _google_id_token
    from google.auth.transport import requests as _google_requests
    OAUTH_OK = True
except ImportError:
    OAUTH_OK = False

# ─────────────────────────────────────────────────────────────────────────────
# 🔒 CHARGEMENT SÉCURISÉ DES SECRETS DEPUIS .env
#
#   JAMAIS de credentials en dur dans le code source.
#   Créez un fichier .env à la racine du projet (jamais pushé sur GitHub) :
#
#     # Google OAuth
#     GOOGLE_CLIENT_ID="YOUR_CLIENT_ID"
#     GOOGLE_CLIENT_SECRET="YOUR_CLIENT-SECRET"
#     ADMIN_PASSWORD=VotreMotDePasseAdmin
#     REDIRECT_URI=https://hemerson-trustlink.streamlit.app/oauth2callback
#
#   Ajoutez dans .gitignore :  .env  trustlink_saas.json
# ─────────────────────────────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    # override=True : les valeurs .env écrasent les variables d'environnement
    # existantes → garantit que la version locale fait foi en développement
    _dotenv_loaded = load_dotenv(override=True)
    if _dotenv_loaded:
        print("[ENV] ✅ Fichier .env chargé avec succès")
    else:
        print("[ENV] ⚠️  Aucun fichier .env trouvé — variables système utilisées")
except ImportError:
    print("[ENV] ⚠️  python-dotenv non installé (pip install python-dotenv)")
    print("[ENV]     Les variables doivent être dans l'environnement système")

def _require_env(key: str, fallback: str = "") -> str:
    val = os.environ.get(key, fallback)
    if not val:
        print(f"[SECURITE] ⚠️  Variable d'environnement manquante : {key}")
    return val

_CLIENT_ID     = _require_env("GOOGLE_CLIENT_ID",     "xxxx")
_CLIENT_SECRET = _require_env("GOOGLE_CLIENT_SECRET", "xxxx")
_REDIRECT_URI  = _require_env("REDIRECT_URI",         "https://hemerson-trustlink.streamlit.app/oauth2callback")
_ADMIN_PLAIN   = _require_env("ADMIN_PASSWORD",       "xxxx")

_SCOPES        = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]
_OAUTH_CONFIG  = {
    "web": {
        "client_id":                   _CLIENT_ID,
        "client_secret":               _CLIENT_SECRET,
        "redirect_uris":               [_REDIRECT_URI],
        "auth_uri":                    "https://accounts.google.com/o/oauth2/auth",
        "token_uri":                   "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 🛡️  WHITELIST — seuls ces emails Google sont autorisés
#
#   Ajoutez ici les emails des analystes autorisés.
#   Tout autre compte Gmail sera refusé même avec credentials valides.
#   Si vide → mode développement (tous comptes acceptés).
# ─────────────────────────────────────────────────────────────────────────────
_ALLOWED_GOOGLE_EMAILS: set[str] = {
    # "analyste@trustlink.ci",
    # "directeur@trustlink.ci",
}
_WHITELIST_ACTIVE = len(_ALLOWED_GOOGLE_EMAILS) > 0

# ─────────────────────────────────────────────────────────────────────────────
# ⏱️  EXPIRATION DE SESSION — 30 min d'inactivité → déconnexion automatique
# ─────────────────────────────────────────────────────────────────────────────
_SESSION_TIMEOUT_SEC = 30 * 60   # 30 minutes

# ─────────────────────────────────────────────────────────────────────────────
# COMPTE ADMIN — seul autorisé à utiliser la voie B
# ─────────────────────────────────────────────────────────────────────────────
_ADMIN_EMAIL   = "sonioff09@gmail.com"
_ADMIN_NAME    = "Hemerson"

# ─────────────────────────────────────────────────────────────────────────────
# UTILITAIRES CRYPTO
# ─────────────────────────────────────────────────────────────────────────────
def _hash(password: str) -> str:
    """PBKDF2-HMAC-SHA256 — salt aléatoire 32 bytes, 310 000 itérations."""
    salt = os.urandom(32)
    dk   = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return base64.b64encode(salt + dk).decode()

def _verify(password: str, stored: str) -> bool:
    """Vérification timing-safe du mot de passe contre son hash."""
    try:
        raw  = base64.b64decode(stored.encode())
        salt, stored_dk = raw[:32], raw[32:]
        dk   = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
        return hmac.compare_digest(dk, stored_dk)
    except Exception:
        return False

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS OAUTH  (avec PKCE S256 — state + code_verifier dans session_state)
# ─────────────────────────────────────────────────────────────────────────────
# ARCHITECTURE PKCE POUR STREAMLIT :
#   Streamlit recrée le script à chaque requête → le Flow (objet) est perdu.
#   Solution : générer nous-mêmes le code_verifier et le code_challenge (PKCE S256),
#   stocker le code_verifier dans st.session_state (simple string, sérialisable),
#   recréer le Flow au callback et lui réinjecter le code_verifier avant fetch_token.

import secrets as _secrets
import hashlib as _hashlib
import json as _json

# ─────────────────────────────────────────────────────────────────────────────
# POURQUOI LE CODE_VERIFIER EST ENCODÉ DANS LE STATE ?
#
#   Streamlit crée une NOUVELLE session à chaque rechargement de page.
#   Quand Google redirige vers ?code=...&state=..., c'est une nouvelle requête HTTP
#   → nouveau session_state vide → code_verifier perdu si stocké dans session_state.
#
#   Solution : encoder le code_verifier directement dans le paramètre `state`
#   envoyé à Google. Google nous le renvoie intact dans le callback.
#   Format : state = base64( JSON({ "csrf": <random>, "cv": <code_verifier> }) )
#   Le code_verifier ne quitte pas notre domaine (il reste dans l'URL de retour).
# ─────────────────────────────────────────────────────────────────────────────

def _build_state(code_verifier: str) -> str:
    """Encode csrf + code_verifier dans le paramètre state (base64 JSON)."""
    payload = _json.dumps({"csrf": _secrets.token_urlsafe(16), "cv": code_verifier})
    return base64.urlsafe_b64encode(payload.encode()).decode()

def _parse_state(state: str) -> tuple[str, str]:
    """Décode le state et retourne (csrf, code_verifier). Lève ValueError si invalide."""
    raw     = base64.urlsafe_b64decode(state.encode() + b"==")  # padding tolérant
    payload = _json.loads(raw)
    return payload["csrf"], payload["cv"]

def _generate_pkce_challenge(code_verifier: str) -> str:
    """Calcule le code_challenge S256 depuis le code_verifier."""
    digest = _hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

def _make_flow(state: str | None = None) -> "Flow":
    """Crée un Flow OAuth de base."""
    kwargs = {"state": state} if state else {}
    flow = Flow.from_client_config(_OAUTH_CONFIG, scopes=_SCOPES, **kwargs)
    flow.redirect_uri = _REDIRECT_URI
    return flow

def _get_auth_url() -> str:
    """
    Génère l'URL Google OAuth avec PKCE S256.
    Le code_verifier est encodé dans le paramètre `state` pour survivre
    au rechargement de session Streamlit lors du callback.
    """
    code_verifier  = _secrets.token_urlsafe(64)
    code_challenge = _generate_pkce_challenge(code_verifier)
    state_encoded  = _build_state(code_verifier)

    flow = _make_flow()
    auth_url, _ = flow.authorization_url(
        access_type            = "offline",
        prompt                 = "select_account",
        include_granted_scopes = "true",
        state                  = state_encoded,
        code_challenge         = code_challenge,
        code_challenge_method  = "S256",
    )
    print(f"[OAuth DEBUG] URL générée. PKCE S256 OK | code_verifier encodé dans state")
    return auth_url

def _exchange_code(code: str, state: str) -> dict | None:
    """
    Décode le state pour récupérer le code_verifier, recrée le flow,
    échange le code via PKCE S256, puis appelle userinfo.
    """
    import requests as _req
    import traceback

    try:
        # Extraction du code_verifier depuis le state (survivit au reload)
        print(f"[OAuth DEBUG] Etape 1 — décodage du state PKCE...")
        try:
            _csrf, code_verifier = _parse_state(state)
        except Exception as e:
            st.session_state["_oauth_err"] = (
                f"State OAuth invalide ou corrompu : {e}. Veuillez recommencer."
            )
            print(f"[OAuth DEBUG] ERREUR décodage state : {e}")
            return None

        if not code_verifier:
            st.session_state["_oauth_err"] = "code_verifier vide. Veuillez recommencer."
            return None

        print(f"[OAuth DEBUG] Etape 2 — recréation du flow avec state...")
        flow = _make_flow(state=state)

        print(f"[OAuth DEBUG] Etape 3 — fetch_token avec code_verifier PKCE S256")
        flow.fetch_token(
            code          = code,
            code_verifier = code_verifier,
        )

        creds = flow.credentials
        print(f"[OAuth DEBUG] Etape 4 — credentials OK. "
              f"token={'OK' if creds.token else 'MANQUANT'}")

        # Appel direct API userinfo
        print("[OAuth DEBUG] Etape 5 — appel API userinfo...")
        resp = _req.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {creds.token}"},
            timeout=10,
        )
        print(f"[OAuth DEBUG] Etape 6 — HTTP {resp.status_code}")

        if resp.status_code == 200:
            info = resp.json()
            print(f"[OAuth DEBUG] Etape 7 — email={info.get('email')}, "
                  f"verified={info.get('email_verified')}")
            if not info.get("email_verified", False):
                st.session_state["_oauth_err"] = "Compte Google non vérifié."
                return None
            # 🛡️ Vérification whitelist
            email = info.get("email", "")
            if _WHITELIST_ACTIVE and email not in _ALLOWED_GOOGLE_EMAILS:
                st.session_state["_oauth_err"] = (
                    f"Accès refusé. Ce compte ({email}) n'est pas autorisé à accéder à TrustLink."
                )
                print(f"[SECURITE] ⛔ Tentative d'accès refusée : {email}")
                return None
            return {
                "email":   email,
                "nom":     info.get("name", email),
                "picture": info.get("picture", ""),
            }

        # Fallback id_token
        if creds.id_token:
            print("[OAuth DEBUG] Fallback id_token...")
            id_info = _google_id_token.verify_oauth2_token(
                creds.id_token, _google_requests.Request(),
                _CLIENT_ID, clock_skew_in_seconds=15,
            )
            if id_info.get("email_verified", False):
                email = id_info.get("email", "")
                # 🛡️ Vérification whitelist (fallback aussi)
                if _WHITELIST_ACTIVE and email not in _ALLOWED_GOOGLE_EMAILS:
                    st.session_state["_oauth_err"] = (
                        f"Accès refusé. Ce compte ({email}) n'est pas autorisé."
                    )
                    print(f"[SECURITE] ⛔ Tentative d'accès refusée (fallback) : {email}")
                    return None
                return {
                    "email":   email,
                    "nom":     id_info.get("name", email),
                    "picture": id_info.get("picture", ""),
                }

        st.session_state["_oauth_err"] = (
            f"Impossible de récupérer les infos utilisateur "
            f"(HTTP {resp.status_code} : {resp.text[:150]})"
        )
        return None

    except Exception as exc:
        print(f"[OAuth DEBUG] EXCEPTION: {type(exc).__name__}: {exc}")
        print(traceback.format_exc())
        st.session_state["_oauth_err"] = f"{type(exc).__name__}: {exc}"
        return None

# ─────────────────────────────────────────────────────────────────────────────
# INITIALISATION SESSION STATE (idempotente)
# ─────────────────────────────────────────────────────────────────────────────
_DEFAULTS = {
    "authenticated":        False,
    "user_email":           "",
    "user_nom":             "",
    "user_role":            "",          # "admin" | "google"
    "user_picture":         "",
    "login_type":           "",
    "login_attempts":       0,
    "locked_until":         None,
    "_oauth_state":         None,
    "_oauth_code_verifier": None,
    "_oauth_err":           None,
    "_admin_hash":          None,
    "_last_activity":       None,        # ⏱️ timestamp dernière activité (expiration session)
}
for _k, _v in _DEFAULTS.items():
    if _k not in st.session_state:
        st.session_state[_k] = _v

# Génère le hash admin une seule fois par session (évite de le stocker en clair)
if st.session_state._admin_hash is None:
    st.session_state._admin_hash = _hash(_ADMIN_PLAIN)

# ─────────────────────────────────────────────────────────────────────────────
# ⏱️  EXPIRATION DE SESSION — vérifié à chaque rechargement de page
# ─────────────────────────────────────────────────────────────────────────────
def _touch_activity():
    """Met à jour le timestamp de dernière activité."""
    st.session_state["_last_activity"] = _time.time()

def _check_session_expiry():
    """Déconnecte l'utilisateur si inactif depuis plus de _SESSION_TIMEOUT_SEC."""
    if not st.session_state.authenticated:
        return
    last = st.session_state.get("_last_activity")
    if last is None:
        _touch_activity()
        return
    if _time.time() - last > _SESSION_TIMEOUT_SEC:
        print(f"[SECURITE] ⏱️  Session expirée pour {st.session_state.user_email}")
        for k in list(st.session_state.keys()):
            del st.session_state[k]
        st.warning("⏱️ Votre session a expiré après 30 minutes d'inactivité. Veuillez vous reconnecter.")
        st.rerun()

# Vérification expiration à chaque chargement
_check_session_expiry()
# Mise à jour activité si connecté
if st.session_state.authenticated:
    _touch_activity()

# ─────────────────────────────────────────────────────────────────────────────
# ANTI-BRUTE-FORCE
# ─────────────────────────────────────────────────────────────────────────────
def _locked() -> bool:
    if st.session_state.locked_until and _time.time() < st.session_state.locked_until:
        return True
    if st.session_state.locked_until and _time.time() >= st.session_state.locked_until:
        st.session_state.locked_until   = None
        st.session_state.login_attempts = 0
    return False

def _fail():
    st.session_state.login_attempts += 1
    if st.session_state.login_attempts >= 5:
        st.session_state.locked_until   = _time.time() + 300   # 5 minutes
        st.session_state.login_attempts = 0

# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# CALLBACK OAUTH — lit ?code=& state= et échange via un flow recréé (sans PKCE)
# ─────────────────────────────────────────────────────────────────────────────
_qp = st.query_params.to_dict()

print(f"[OAuth DEBUG] Script rechargé. Params={list(_qp.keys())} | "
      f"authenticated={st.session_state.authenticated}")

if not st.session_state.authenticated and "code" in _qp:
    _code           = _qp.get("code", "")
    _state_from_url = _qp.get("state", "")
    # Utilise le state de l'URL en priorité (le session_state peut être vide si reload)
    _state_to_use   = _state_from_url or st.session_state.get("_oauth_state", "")

    print(f"[OAuth DEBUG] code reçu ({len(_code)} cars) | state={_state_to_use[:25]}...")

    # Nettoyage immédiat de l'URL
    st.query_params.clear()

    if not OAUTH_OK:
        st.session_state["_oauth_err"] = "pip install google-auth-oauthlib google-auth requests"
    else:
        with st.spinner("Connexion Google en cours..."):
            _info = _exchange_code(_code, _state_to_use)

        if _info and _info.get("email"):
            st.session_state.authenticated       = True
            st.session_state.user_email          = _info["email"]
            st.session_state.user_nom            = _info["nom"]
            st.session_state.user_picture        = _info.get("picture", "")
            st.session_state.user_role           = "google"
            st.session_state.login_type          = "google"
            st.session_state.login_attempts      = 0
            st.session_state["_oauth_state"]     = None
            _touch_activity()
            print(f"[OAuth DEBUG] SUCCES — connecté : {_info['email']}")
            st.rerun()
        else:
            _err = st.session_state.get("_oauth_err", "Erreur inconnue — voir terminal")
            print(f"[OAuth DEBUG] ECHEC — {_err}")

# ─────────────────────────────────────────────────────────────────────────────
# PAGE DE CONNEXION
# ─────────────────────────────────────────────────────────────────────────────
if not st.session_state.authenticated:

    # ── CSS page login ───────────────────────────────────────────────────────
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700;800;900&display=swap');
    html, body, [class*="css"], .stApp {
        font-family: 'Poppins', sans-serif !important;
        background: linear-gradient(135deg, #0a0e27 0%, #050812 50%, #0f1436 100%) !important;
        color: #ffffff !important;
    }
    #MainMenu, footer { display: none !important; }
    [data-testid="stHeader"] { display: none !important; }
    /* Bouton principal */
    .stButton > button {
        background: linear-gradient(135deg, #4f7bff 0%, #00d4ff 100%) !important;
        color: white !important; border: none !important; border-radius: 12px !important;
        padding: 0.9rem 2rem !important; font-weight: 900 !important; font-size: 15px !important;
        letter-spacing: 1px !important; width: 100% !important;
        box-shadow: 0 6px 20px rgba(79,123,255,0.4) !important;
        transition: all 0.3s ease !important;
    }
    .stButton > button:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 10px 28px rgba(79,123,255,0.55) !important;
    }
    /* Champs texte — contraste maximum */
    .stTextInput input {
        background: #1e2d5e !important;
        border: 2.5px solid #5a7adf !important;
        color: #ffffff !important;
        font-weight: 700 !important;
        font-size: 15px !important;
        border-radius: 10px !important;
        padding: 0.85rem 1rem !important;
        caret-color: #00d4ff !important;
    }
    .stTextInput input::placeholder {
        color: #7a9ad4 !important;
        font-weight: 500 !important;
        font-style: italic !important;
        opacity: 1 !important;
    }
    .stTextInput input:focus {
        border-color: #00d4ff !important;
        box-shadow: 0 0 0 3px rgba(0,212,255,0.18) !important;
        background: #243578 !important;
        outline: none !important;
    }
    /* Labels champs */
    .stTextInput label, .stTextInput > label {
        color: #b8cfff !important;
        font-weight: 800 !important;
        font-size: 11.5px !important;
        text-transform: uppercase !important;
        letter-spacing: 1.8px !important;
    }
    </style>
    """, unsafe_allow_html=True)


    # ── Logo INSSEDS en haut de page ─────────────────────────────────────────
    st.markdown("""
    <div style="position:fixed;top:0;left:0;right:0;z-index:99;
        background:rgba(5,8,18,0.92);backdrop-filter:blur(8px);
        padding:10px 28px 10px 60px;display:flex;align-items:center;gap:16px;
        border-bottom:2px solid #3a5adf;box-shadow:0 4px 18px rgba(79,123,255,0.25);">
        <img src="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAAkGBxESEhUTEBIWFRUWFxUbFxcVGRceFRsWGxcdHRkXGRgeKDQkHh8nIBkZJTMjJiwtMDAvHiI0OD8uNyktMS0BCgoKDg0OGBAQGi0lHyUtLS8tLS0tLy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLf/AABEIAMgAyAMBEQACEQEDEQH/xAAbAAEAAgMBAQAAAAAAAAAAAAAABAUBAgMGB//EAEwQAAIAAwMFDAYJAwMBCQEAAAECAAMRBBIhBSIxQdEGExUyUVJTYXGBkZIWQkNzk7EHFCNygqHBwtIzYvCio7LiJCU0NVRkg+HxF//EABsBAQACAwEBAAAAAAAAAAAAAAABAgMEBQYH/8QAMhEAAgECBQMEAQMEAQUAAAAAAAECAwQREhMhUQUVMQYUQVIyIjRhI0JxkSQWJTNigf/aAAwDAQACEQMRAD8A+4wAgBACAEAIAQAgBACAMQAiNwIkbCA2MwAgBACAEAIAQAgBACAEAcZtoVdJ0aeSGBGJHGVJeoTG61luw8QKROUjMOE05k34U3ZDAZhwmnMm/Cm7IYDMOE05k34U3ZDAZhwmnMm/Cm7IYDMOE05k34U3ZDAZhwmnMm/Cm7IYDMOE05k34U3ZDAZhwmnMm/Cm7IYDMOE05k34U3ZDKycxxn5blIKsJgHKZcwfpE5WRmNZeX5LGgEyvJvb1py6IZGRnRI4UTmTfhTNkRlZOZDhNOZN+FN2QwGYcJpzJvwpuyGAzDhNOZN+FN2QwGYcJpzJvwpuyGAzDhNOZN+FN2QwGYcJpzJvwpuyGAzDhNOZN+FN2QwGYcJpzJvwpuyGAzDhNOZN+FN2QwGYwcqS9YmL1tLdR4kUhlGYkyrQraDp0ckQWINnlCY7FsVQgAar9A149gIp39UWZVFpFSwgBACAEAIAQAgBAHG0zgiliaACsPJHgh2GzFjvswY+op9UfyP5aO2zZCJFtsgmDkYcVhpU/wCatcQngGjnk+0FgVfB1NGGqvKOo6YMlE6IJEAIAQAgBACAEAIAQBV2iUJbqVwVyQRqD0LXh2gGvdFkVOuSva+8/YkGET4qWEAIAQAgBACAEAIAq532s0J6iUZus+qv69w5Ystir3LOKk+DMCStyktxhOGgZr/c1N+E/kWiy32KssEaoipY2gBACAEAIAQAgBACAIGVfZ+8/Y8SirGS/ae8/YsH8BE+KlhEgQAgBACAEAIAjW60CWhY6hoGk9Q64lLEhs1ydZyiZ3GOcx/uOnuGjsEGES4gkQBpMQMCCKgih7IAg5Lci9KY1KGmOkr6p8PzBiZERLGIJEAIAQAgBAGCwEAZgBAEDKvsvefsaJRVjJftPefsWD+AifFSwiQIAQAgBACAMQBWzPtZwX1ZdGb73qD5nuWLLYqyzipYQAgBAFblAXHSaNHEfsJzT3H/AJGJRVlipqIgsZgBACAMEwBwM4nBBXr1CAOVpsZZCLxvEYHUD2QBpki1l1o2DLgw6xAFhAEDKvsvefsaJRVjJftPefsWD+AifFSwiQIAQAgBACAI1ttARCx1DVp7uuBBpk2zlEzuOxvP946u4UHdEsImRBIgBACAOc+UHUqwqCCCOowRDIeS5poZbnOQ3T18jd4oYlhFhEEiAOMyeBgMTyCANRKLcc/hGjvgCsypl6XJDCXdmMoIuK2cHoWVSADSoV+8UAJMAW8pwygggggEEaCDrEAVtslGXNWamhsHHXqaGwwIe6PLrykP1WXv8wEXkFcAeUgadGEYqk2vBvWltGrL+q8EdUacZckzwA5fEDQDvbYRmh4NOuoqX6Sdkv2nvP2LB/BjRPipYRIEAIAQAgBAFY32s6nqS6E8hf1R3cbyxYqWcVLCAEAaTZoUVJpAHBbTiKqQDoJ/zCAJUAVuUVuMs4aBmv8Ac1N+E/kTFkVZNM4AVJipY0zm/tH+o7IAjNbpaM0tVZmVS7XRjhSgJJGLVw1ZrYikAUE3KdotuZZ1aUlHq5JGcrS8xnTGWSpcjSCChzhUQBc5NyJLlgFxeYEtjiFLFWaldNXQPU+tU4QDOttysiZozmOhVxJ7B+ujriGzLCjm8kZLFOnGs5ii8xTnfiYaOxfExXDHyXzQpvCO/wDJaWazJLUKihQNQGEWwS8GGU3J7kbKns/efseLox/JnJftPefsWIfwET4qWESBACANWYDTAERrYWNJQvHl9Ud8AaWhmly2d2vECpA0U5BBENnXJsgogB4xzm+8cTs7AIlsIlxBJisARntFTdQVPLqHaYAwJQWrzGBoCSWwVQNJ6u2ANkdJyVRgynQymoqDy9REAZsswnNbjLgdsPkGtptEsEI7LV6gKSM7DEAa8IjMsS2nJrFLZEbJNBeRsXlmlTpK+qfCleusWkY0Ve6HK09JwkyKVaXRQTnM71usgocFuUY+rfDEUGMFixyXYnokycW30KyNW5VlJqA4Wow1UJ144mA2O02fIsyAAKijQqgAY6gBEN4eS8YSlsiHetFo0fZS+UjPI6lOj8XhFfJmShT87sn2LJ0uUM0YnSxxY9pMWUcDFKrKRNiTGIAgZV9l7z9jRKKsZL9p7z9iwfwET4qWESDBMARJltxuyxebq0DtMAaPZ8C09xQYkVogHWYA4WnLciU6SgbzFit2XQ3aXb1RXVfUmmIGOgGAJNpz3RNQz27Acwd7Y/gMSVZJl4VHJo7IgsazbSq6TjyDTEYk4M5XGfjZq8g0ntMSQRcq5XlWVDXjBbwQV4t9VvtQGi1YVPbpgCmk2e0Wz+ozLKKXcHzSCaTFa4aMxUuhPqNLDLxoAvrHISzS7t8kCpq12vXgoAHcBrOkmBKWJEW1zJzVkKAujfWGFP7R63bo6zFMW/BnUIwX6il3S2FZM6xzKlmM8BnbFjeRvAdQwjHUWElgblrVc6VSGHwegtouPLmjQaI3fxD41H4o2Vucp7MsJk9VW8xAHKYoy0U2VLZRmzsLMub0jcX8PO7sOuK4t/iZ1TjDep/okWLJCob7kzJnObV90aB3d9YlR5KyrN7LZFlSLGEQBmAEAQMq+y95+xolFWMl+095+xYP4CJ0VLEWbbADdUFm5BEg0Fld8ZrUHNX9TAEa25as8hRQipAKqMKg6MdAwBOOpWOowHkqpz2yeWVSM1pgBSolEErvbM5qJgWkxHTA9WgwGxZ2PIElFo4E0VvfaAGhC3Qcdd0KCddK6zD+B4NpeUERTNY4zDmjXd9RQNJNMaDWxhJ4bFqdNz3RgG0TtH2ScpA3wjqXQv4q9kUTbM2FOHnco50r6tlGTdLETJUwNUkklSrVx10rGPxJG5F6ttNv+3A9LlQzt7DWci8CGphnLzRXAVw/+tIznL3Kzc/uf3kX5zBnxOAoReWjhzWj4BKmgqUDHGGAJtpymFO9yVvvTBV0AdeoDt7qxVvgzRovzLZGknJbOb1pN48wcQdvOPbh1CISx/Il1Yx2p/7LYCmiLmBts8vu9FEs7c20yfzan6xiqnQ6fjmklwWNstquhlS1MxyKELoU8rNoX59UXUsPBqujvjJ4Ij5NsRnY2k3mUkGWMJYI6vW5cerARLjj+Q1ktof/AEv1UDREmJvE2gQIAQAgBAEDKvsvefsaJRVkexWtVMwaW3zADTxFg/gIk7zMfjm6OaunvMR8lg9pkySiFghc0UcprQVPWSBjrIEAUZtdrtAaXQS2CMGVGYXZqzPWmihAZKMlKVxqaQB1yLubMtzMnkM5CiqsaNhVwwwBF8u1P7jhQKABcT7VKkriVUDAAUAHIBsiGy0KbkU1rtE60sJSAy0YG8zYNc10Xr0Z1OyEX8mRxhD8ty3sWTJcvEAs9MXbFuzqHUKCGG+JWVVvb4J0SYzyu63MtFim8k653TEZdkYan5JnSs3jRqw5LydaVkglzRdXadUZWzQjTlLwQws+0aaypf8AuN3er349Qivky/oprlllZLGksURaD8yeUnWesxZLDwYZTlPdkiJKiAIWVMmS7QlyaKrVWwJBqpqMR1xWUcxlo150pZoM72azJLUKihQNAAwiUsPBSc3J4yIdsG9OJo4rUEzq5r/oe7kiyWJjexYq1REFjaAEAIAQAgCBlX2XvP2NEoqyuyBMuTZ0tqYvVTrOYtR/nXEsI2yxMn37qhyC0tpZlhqc2bLmEaBdJYMdZ5VFaljnk/cvLQq0xiXQUBVmGOhnrpq91Cw517nNUC6tVrSWCXYADTUxDeHktGDk8EV31mfO/pLcXnuD/pXAnvoO2K4t+DMoQjvLzwGssuRntWZM0KWxYk+qg0L3U64soFJ129lsiZk6zFQWfjti1NA5FHUNp1xZmFE2IJMQBS7qMkvaZSrLYK6zJbqW0VVgdsUqRxNq0rqjPGXgk2TJgUh5h3yZzjoH3V0L8+UmJSMc6ze0dkWIixhMwAgBACAEAaugIIIqDpGqAKyW5kG69TLOCMfV/sb9D+um3kr4LRWroiuGBOJmBIgBACAIGVfZe8/Y0SirK95BImOnHSZUeRYlhFoLclwOxoCK46uWsUMii2Qfr02dhZ1ovSPUL3DS3dQdcVxb8GZU4Q3m9+DvZslIpDzCZjjQzaAf7V0Dt09cSo8lZVm9orBG1ot4BuSxffmjV1sfVH+YxdIwSkzay2Mg35hvP/pUcij9df5Qf8DAnRBIgDEAIB/wIAQI8GYEiAEAIAQAgDSYgYUIqDgQdEMRgVxs8yVjKz06MnOH3CfkfGLeSvgk2W3o+ANGGlWwYdoiGiUyXEEiAEAQMq+y95+xolFWefm7o5cqZNkjj3wTUNdUFFpW6Ce75RiqVlB4Nm1Qt8/6mbSMo2KoadOMxtIrLmBAf7Up+ZqeuMSr0+TM4VcMIxwRMn7rbKozSzHkCP8AqIsrmlyYHbVeCL6QSZn9WeUXmy0m173u/KnbE+6pL5I9rWfwTLPugsKCiPQdUuZ48XTD3NPkn2tTg6+lNk6Q/DmfxiPc0+R7apwPSiydIfhzP4w9zT5HtavA9KLJ0h+HM/jD3NPke2q8GfSiydIfhzP4w9zS5HtqvA9KLJ0h+HM/jEe6pcj2tXgelFk6Q/Dmfxifc0+R7apwPSiydIfhzP4w9zT5HtqvBj0psnSH4cz+MPc0+R7arwPSmydIfhzP4w9zT5HtqvA9KbJ0h+HM/jD3NPke1q8D0osnSHyTP4w9zT5HtqvA9KbJ0h+HM/jD3NNfI9tV4HpRZOkPkmfxiPc0uR7WrwZ9KLJ0h+HM/jE+5pcj2tXgx6U2TpD8OZ/GHuKXI9tV4I9qy5YJlLzmo0EJNDDsIFREq6pr5DtanBGG6GXL4k/fByOkwN5guPeO+Jd1TfyQrSpwS7PuuszDOLKeQo/6AxV3FLkn21Xg7elFk6Q+SZ/GHuaXI9rV4OE7LtnnTJUuXMq94tQq4wCMCRUDlEZaVWEvBiqUpx8nyPdxaXl5SnMpoczvFxY0bxNzOhZ/jiMm255zqgahavbgK0A1k0oBrNI1IxxeBuOphEkTWmhbwdbpcoLzKr1ABNVY4aYs6eBRVUzeWk84kqPtJaUDoWJmCqlRXOBHJthpNjWSOdmac5ADKtUdxemIM1VvVxOGAwr8ojTZLqxMpv7GiAnBNJUVLpeAFTjhjhqxhpMasTks6edAPqax7RC6eKgmCgydRHOdbZqtdNa0BwNRQ6CCMCIq4slTTJGTpsyaXALZi3iFUsxF5VwX8UWjAiU0aibONLuIYkKCVDEVIvXa1pgcdGBxidMjVRuotJrQVpdxDJQ3q3bprRq3TSldERpsnViay2tDBSqk3qUAZb2cKrVa1FRorphpyGrE2cWkUza1KgXWU1vcU4HQccdGETpMjWidHSdQsrKQGlqM9KsXDUuY5wqrDD9DRpMjWicWecKDXVwc5LouKrNV60FL4rXRBwZOqiPMt81WKmtRpEUcWXU0drHay4dnmXAgFcCTiaaIsoYlZVEbzmnKWFVNylSHXQaUehNbucuNNcS6eBVVUZtJno8xKqxllg110PF4xArU014Ya6REqe5MaqaMJNmGUswMTea6oUE51QLpOpscBE6ew1FiY3yd2moGayFdDHFgaCl09lDWI05E6sTP/aaE0wGu8uOZezcc7NxwrhDTkhqxNd8n4DAZt7F0F0YYvU5nGXjU0iGmxqoiz8pzEJVqhlJBB0gjVFGsCyliTtwU93ygjE1N19PJSN2zSxZpXreCIX0hj/vGd/8AH/wWJuvySIs/BRyJgVgSocc03qHykGNNNJ4m5L+GWbZecsGaWjEMGFb+H2ay6aeai4nGorWMmozHprkyd0EwvfKISHkOK3zRpK3V9apqNNaw1GNNHKTll1VFuKVQOuN81DoVYVrmihJotMYhVP4JcEd7Bl666GZLVlUyiKXry72gSq4jEhRp1xMav8ESppmsndBMQLdRAw3urC/eYJLaUoOdhmORm0MNQh00Q52UZpmGYrurEAVDvWnJeJJ1csVc2ZFBGbPlF1Llxvu+LdbfC5qLysMQQfUGuGZkOKOsvK5FykqXVAyg5/8ATa9VDnaM9hXT1xOdkZEbLluYCl1EAlvKZFF6g3u9QYmuJdiYZ2NNGZeW3UCiJeogZs6rCWl1AcaaKaKaBE6jI00a2XLc2WVKhaqJYGnQhJGvXWIVRkumjcZcmVJKhs+U4vNMYhpd67iWr67YdcS6jIVNHOxZZmSgAoFAZpOLAnfAgIqpBH9NaUiM5MqaxODZQm32dXdSxxuu9TyVJNT3mKuZbIsDazZQZb99Vm75S9vhfSDWtVIMSpshwXJJfL00o6FV+0rUi8MDdwoDTC4AKjARbUZXTRu26CZ9qRLQGaZpYi/pmJdf1sdJIBqASYajbCppEfJ+Vnkr9mihjdq5vkkK4cVFbulRqiFNpEummzez5aaWaypaIL1aKX5jKcb1Rg50HkiVUZDppmHy1MJBoDQsReLsc5AmliToEHUYVNI3l5dcMXCKGZLrlTMBbFTWobA1QHNprhqDTK2dNLMzHSxJOJOnrNSe+MTxZkisD030b/8Ajk+6/wAo3LT8mal6/wBKPbWjJcu1TppugUYXnugtxFoorGn1rqUbWKSWMmaVFzx2NxuMsvNPi22PHy61cN+Tb3x8mfQyy80+LbYr3q45G49DLLzT4tth3q45G49DLLzT5m2w73c8jcehll5p8W2w71c8jcx6GWXmnzNth3q45IwY9C7LzT5m2w71cck7j0MsvNPi22Hernkbj0MsvNPmbbDvVxyNx6F2XmnzNth3q45G/Jn0MsvNPmbbDvVzyNzHoZZeafM22I71c8jcehll5p8zbYnvVzyNx6GWXmnzNth3q55Bn0MsvNPmbbDvVzyNx6GWXmnzNth3q45G5j0MsvNPmbbDvNxyNx6GWXmnzNth3m55G49DLLzT5m2w7zcchYj0LsvNPmbbDvVxyN+TPoZZeafM22Hernkbj0MsvNPi22Hern7Awdxll5p8W2xaPW7lfJG5rZsmy7JOlG6DeYhXugNxGqpp/mHVHsOi9RheQae0katZy2xLLIAzH65jfJY8z6keNyzJQ8FpHmzOIEiAEWUW/CIbS8iDi08MBihEuLXlDFCChJ+EMTERg8fA2MxbSn5Sf+iM0eTEVcWngycUxEqEn4RDaXkRLhJeUTjj4MxCg5fisRjyItpT+rIzIxFXGS2aGK8mYtpz4f8AoZlyIq4yXlE4r4ERg34GPyIvpT4f+iMy5EUf8k7CAEVJEAVe6AZidUxfkY9J6af/ACUa9fwZyBxH943yEV9R/uWKHgs486ZxAkQB4/6SJ7pKlFGZSZhBukj1THt/RdvCtcSU1ijjdXm4wWBx3OWlzkuexdiwFooxJqKLhjGTqtvTj1lU4rbEm1m5WmPyeWyHujmyJyu7s6aHUknNOsdY0/8A7Hses+n6Fza4U44SS2ORZ3s6db9XgvvpCt7XpDSZhCtLYgqxAIqKHCPPekLCDVeNWOLRu9Vryxg4vZk7KGWJsjJlmdCb8xJKlziRWXUntwjndN6bRuurShU8J+DauriVK1Tj5POZPsb2mU0z63SeC1JTNnNTRnEjTHqru4haVtJ2/wDT5OXSputDMp/qPYbjVtyB0tam6KFGZlLdanGvJ+ceI9QqxqVYSttsXudmx14waqHj52V5lrtN2dP3mWSwxrdUCtBSox6zHt6FhS6fYqpRp55YHGlXnWruNSWCLGxZOyhInXrK5nygRiHW466wQWwOkVjlX91066tP68Mk/wDBtW9KvTq/oeMST9JNpmI8i47LVZlbpI1rGD0Ta0arrOSxwLdYqShlwZByRkK12iSk0Wq6HBIDO9RjT9I6F91a2tq7paHgxUbWpOCk6h6LJuTJ9ms1p32dvhKOVIZjdoh1mPK3l5SvL2nlp5Vj4OjRoyo0JYvE8RkOXarVNMqVPYMEL1Z3pQFRqrzhH0DqU7Lp9GM501ukcO1jVryaTJUvLNssE8pOdnCkX0LFlZDrQnqjQuOmWPV7J1qKwfwZqVxWta2So9j0O77Lk2UJaSWuiYpYsNJGFAD3/KOB6S6RRrVak6qxy+Eb3VbqcIxUfDKGTkqbMky5tmte+TjdLSla66k6cS2rsj0E7+jTqujcUMsOfJpRt5OOenPc91uXNq3m7bFImKxAJKkslBQmmvSO6PnfXFae5btX+k71nqaf9TyW8cXY2vgzFSRAFXug4ie8X5GPRem/3SNev4M5A4j+8b5CHqT90xQ8FnHnTOIEiAPGfSd/Rk+8P/Ax730N+4kcPrX/AI0RtzP/AJTaOy0f8Iy9YX/fF/km22szzO57In1rfwv9RJasnWbxqp7dkes6v1V2NWg3+L8nKs7fWhNLyiunWiYVWW+iXfCg6VqcV8RHUtbejFVLil/ejWq1JNRpy+D6KtrsqZOsqWsEpMky6CmsIuvUY+Y0ba7q9TnO18pno51KULdKp8lE+5KVOkm0WOeSgDm7NArm1qLw0aNYj09P1FXo3Ctrqli+Tmvp8JwdSnPA6/R5lebvrSWZml70zgHEqVK6Oo3tEafq/plLLCtBYSZm6TcVG3GTxSOlosWTrfOpImPKmuGbADe2Os3Tr14U1xFvedT6XbKVaOaBM6Vtczai8GUGUrPPydPok3OChgy1AIxwZe7RHoKNS36vZuU4YbGhJTtK6UWXX0izb/1VyKFpbGnJW4aRxfRMFTncRXwbfWXm0znkLcnLnyJc02m4WBN2gwxI5eqL9S9R1be5lCNDHD5IodPhOmm5np7LkpbLYrRLWZvlVmtXkrLpTT/bHkqt7K86hCpKGXFnVjTVO3cE8TyP0cuBbCSQPsJmn78qPZ+saU52lNQWOxyOkzUKksxx+kG0o9qYoQwEtVJGIJxP6xn9M0Klt05urtszH1GcKlwlA9Rl+dYlkyrPbQ19JSEFRnDC7UH8JwjynSKV/r1K9p4x3Opdyo5YwqnnstblN6kfWZM6/LopAYUajEUIIwOnqj1HTfUDurhWtxSwZzbmxVOGpCR6D6OsqTZqTZc1i29FLrHTRgc0nqu/nHlPWXT6NrXjKn/cdPpNac6eEj2EeKOsZiCRAFXug4ie8X5GPR+m/wB0jXr+BkA5j+8b5CHqRf8AJYoeC0jzpnEQSIApN0+QvriIu+XLrXq3a1wpyiO/0PrPbajllzYmleWnuI5cTTJm57ebJMs2+Xr4mZ12lL4porq7Ym8637i9V1lw/gijaadHSxOO5fct9Td332/fULS7SlDXlMZ+ueoO5RgsuXKVsrH2+OD8kbLu4lLRNM1Jm9luMLtQW52kRu9K9XVbK30XHMv8mG56XGtPPjgWk3c9Keyy7LNJYS0RQ4wYFVpeGmn5xyKPWqtG7dzT2x+DbqWkZ0lTkedTcDMWoW1Zh0i4RXtzqGPUf9a05fqlRTlycx9He6Utj0G53c5Ksl4oSztQMx5B6qjUI811jrtbqE1J7JeEdG1s40I4LyU+U9waPM3yRNMqprdK1AP9uIIjs2PrCVGiqVaGY06vSU5ucXgbWPcKl8PaZpm0IJFKBqamNcR1QvfWM50XSoQyotQ6XGM883iWG6jcz9caWd9uXAw4ta1p1jkjndD9Rvprm8mbMZbywVxhv4KT/wDnZ/8AU/7f/VHf/wCuk93RRpdl/wDYt8iblfq8uem+39/ULW7Smaw5TXjRwep+oVeV6dVU8uU3reydKDinjiVA+jv/ANz/ALf/AFR3l67/AEpOljgaPZflSLLJW4mTKdZkxjNZTUAii11EiprSOT1P1dXu6bpwWVG1b9Lp0nme7LHdFuelWtRfJV1rdddIrqI1iOd0frtXp0247p+UbF3ZxuIpM89L3AzALjWqqVrduGnhej0j9aU086orMc/s7xwc9j1GQ8jyrLL3uVXE1ZjxmY6zHj+p9Tq31V1Kh1be3jRjliWMc0zmYqSIAq90HET3i/Ix6P01+6Rr1/BGvtZZrhwd7c1qBW6eWnJT5R6LrfSndxUqf5L45MVKeXyWAyrZz7eX3uo/WPGS6ZcqTWU2NWBnhSz9PK86bYp225+o1Y8jhSz9PK86bYdtufqNWPI4Us/TyvOm2Hbbn6jVjyOFLP08rzpth225+o1Y8jhSz9PK86bYdtufqNWPI4Us/TyvOm2Hbbn6jVjyOFLP08rzpth225+o1Y8jhSz9PK86bYdtufqNWPI4Us/TyvOm2Hbbn6jVjyOFLP08rzpth225+o1Y8jhSz9PK86bYdtufqNWPI4Us/TyvOm2Hbbn6jVjyOFLP08rzpth225+o1Y8jhSz9PK86bYdtufqNWPI4Us/TyvOm2Hbbn6jVjyOFLP08rzpth225+o1Y8jhSz9PK86bYdtufqNWPI4Us/TyvOm2Hbbn6jVjyOFLP08rzpth225+o1Y8jhSz9PK86bYdtufqNWPI4Us/TyvOm2J7Zc/UaseTByrZx7aX3Op/WJXS7l/2jVjyV5drXNQIDvaGtSKXjy05KfOPadD6U7RZ6n5P44NerUzHsZ9mR+OoPbHoDGQzkOzdEPE7YZURghwFZuiHidsMq4JHAVm6IeJ2wyrgDgKzdEPE7YZVwBwFZuiHidsMq4A4Cs3RDxO2GVcAcBWboh4nbDKuAOArN0Q8TthlXAHAVm6IeJ2wyrgDgKzdEPE7YZVwBwFZuiHidsMq4A4Cs3RDxO2GVcAcBWboh4nbDKuAOArN0Q8TthlXAHAVm6IeJ2wyrgDgKzdEPE7YZVwBwFZuiHidsMq4A4Cs3RDxO2GVcAcBWboh4nbDKuAOArN0Q8TthlXAHAVm6IeJ2wyrgDgKzdEPE7YjKgZGQ7N0Q8TtiUkgSpFmROIoHZE4jA7wAgBACAEAIAQAgBACAEAIAQAgBACAEAIAQAgBACAEAIAQB/9k="
             style="height:58px;width:auto;
                    mix-blend-mode:screen;
                    filter:brightness(1.05) contrast(1.05);
                    background:transparent;" />
        <div>
            <div style="font-size:14px;font-weight:800;color:#ffffff;font-family:'Poppins',sans-serif;letter-spacing:1.5px;white-space:nowrap;overflow:visible;">INSSEDS</div>
            <div style="font-size:11px;color:#a0bfff;font-weight:600;
                font-family:'Poppins',sans-serif;">Statistique · Économétrie · Data Science</div>
        </div>
    </div>
    <div style="height:80px;"></div>
    """, unsafe_allow_html=True)

    # ── Splash screen hero ───────────────────────────────────────────────────
    components.html("""
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600;700;800;900&display=swap" rel="stylesheet">
    <style>
      @keyframes pulse-glow {
        0%,100% { filter: drop-shadow(0 0 18px rgba(79,123,255,0.7)); }
        50%      { filter: drop-shadow(0 0 40px rgba(79,123,255,1)); }
      }
      @keyframes float {
        0%,100% { transform: translateY(0px); }
        50%      { transform: translateY(-8px); }
      }
      @keyframes shimmer {
        0%   { opacity:0.5; }
        50%  { opacity:1; }
        100% { opacity:0.5; }
      }
      .star { position:absolute; border-radius:50%; background:#fff; animation:shimmer linear infinite; }
      @keyframes fadeUp {
        from { opacity:0; transform:translateY(30px); }
        to   { opacity:1; transform:translateY(0); }
      }
    </style>
    <div id="hero" style="position:relative;width:100%;min-height:320px;
        background:radial-gradient(ellipse at 50% 30%, #0d2280 0%, #050d3a 45%, #020818 100%);
        border-radius:24px;overflow:hidden;display:flex;flex-direction:column;
        align-items:center;justify-content:center;padding:2.5rem 1rem 2rem;
        box-shadow:0 30px 80px rgba(0,0,50,0.8);border:1.5px solid #1e3070;">

      <!-- Étoiles générées en JS -->
      <canvas id="stars" style="position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none;"></canvas>

      <!-- Lignes réseau (SVG déco) -->
      <svg style="position:absolute;top:0;left:0;width:100%;height:100%;opacity:0.18;pointer-events:none;" xmlns="http://www.w3.org/2000/svg">
        <line x1="10%" y1="20%" x2="40%" y2="50%" stroke="#4f7bff" stroke-width="0.8"/>
        <line x1="40%" y1="50%" x2="70%" y2="15%" stroke="#4f7bff" stroke-width="0.8"/>
        <line x1="70%" y1="15%" x2="95%" y2="60%" stroke="#4f7bff" stroke-width="0.8"/>
        <line x1="5%"  y1="70%" x2="35%" y2="50%" stroke="#4f7bff" stroke-width="0.8"/>
        <line x1="35%" y1="50%" x2="60%" y2="80%" stroke="#4f7bff" stroke-width="0.8"/>
        <line x1="60%" y1="80%" x2="90%" y2="55%" stroke="#4f7bff" stroke-width="0.8"/>
        <circle cx="10%"  cy="20%" r="3" fill="#4f7bff" opacity="0.7"/>
        <circle cx="40%"  cy="50%" r="3" fill="#4f7bff" opacity="0.7"/>
        <circle cx="70%"  cy="15%" r="3" fill="#4f7bff" opacity="0.7"/>
        <circle cx="95%"  cy="60%" r="3" fill="#4f7bff" opacity="0.7"/>
        <circle cx="5%"   cy="70%" r="3" fill="#4f7bff" opacity="0.7"/>
        <circle cx="60%"  cy="80%" r="3" fill="#4f7bff" opacity="0.7"/>
        <circle cx="90%"  cy="55%" r="3" fill="#4f7bff" opacity="0.7"/>
      </svg>

      <!-- Bouclier SVG -->
      <div style="animation:float 3.5s ease-in-out infinite;margin-bottom:1.2rem;position:relative;z-index:2;">
        <svg width="80" height="96" viewBox="0 0 80 96" xmlns="http://www.w3.org/2000/svg"
             style="animation:pulse-glow 2.5s ease-in-out infinite;filter:drop-shadow(0 0 22px rgba(79,123,255,0.8));">
          <defs>
            <linearGradient id="shieldL" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%"   stop-color="#1a3a9f"/>
              <stop offset="100%" stop-color="#0d1f6e"/>
            </linearGradient>
            <linearGradient id="shieldR" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%"   stop-color="#cc1a1a"/>
              <stop offset="100%" stop-color="#8b0000"/>
            </linearGradient>
          </defs>
          <!-- contour bouclier -->
          <path d="M40 4 L76 18 L76 48 C76 68 60 84 40 92 C20 84 4 68 4 48 L4 18 Z"
                fill="none" stroke="#4f7bff" stroke-width="3" opacity="0.9"/>
          <!-- moitié gauche bleue -->
          <path d="M40 4 L4 18 L4 48 C4 68 20 84 40 92 Z" fill="url(#shieldL)"/>
          <!-- moitié droite rouge -->
          <path d="M40 4 L76 18 L76 48 C76 68 60 84 40 92 Z" fill="url(#shieldR)"/>
          <!-- ligne centrale -->
          <line x1="40" y1="4" x2="40" y2="92" stroke="#ffffff" stroke-width="1.5" opacity="0.6"/>
          <!-- lettre H -->
          <text x="40" y="58" text-anchor="middle" font-family="Poppins,sans-serif"
                font-size="26" font-weight="900" fill="white" opacity="0.95">H</text>
        </svg>
      </div>

      <!-- Titre principal -->
      <h1 style="font-family:'Poppins',sans-serif;font-size:clamp(22px,4vw,38px);
          font-weight:900;color:#ffffff;margin:0;text-transform:uppercase;
          letter-spacing:3px;text-align:center;position:relative;z-index:2;
          text-shadow:0 0 30px rgba(79,123,255,0.6);
          animation:fadeUp 0.8s ease both;">
        HEMERSON TRUSTLINK
      </h1>

      <!-- Sous-titre orange -->
      <p style="font-family:'Poppins',sans-serif;font-size:clamp(13px,2vw,17px);
          color:#ff8c00;font-weight:700;margin:0.6rem 0 0;text-align:center;
          position:relative;z-index:2;letter-spacing:0.5px;
          animation:fadeUp 0.9s ease both;">
        Détection Intelligente de Fraude Financière
      </p>

      <!-- Séparateur -->
      <div style="width:60px;height:2px;background:linear-gradient(90deg,#4f7bff,#00d4ff);
          margin:1rem auto;border-radius:2px;position:relative;z-index:2;"></div>

      <!-- Badges tech -->
      <div style="display:flex;flex-wrap:wrap;gap:0.6rem;justify-content:center;
          position:relative;z-index:2;animation:fadeUp 1s ease both;">
        <span style="background:rgba(79,123,255,0.15);border:1px solid rgba(79,123,255,0.4);
            color:#a0bfff;padding:0.3rem 0.9rem;border-radius:20px;
            font-family:'Poppins',sans-serif;font-size:11px;font-weight:700;letter-spacing:0.5px;">
          Machine Learning Avancée
        </span>
        <span style="background:rgba(79,123,255,0.15);border:1px solid rgba(79,123,255,0.4);
            color:#a0bfff;padding:0.3rem 0.9rem;border-radius:20px;
            font-family:'Poppins',sans-serif;font-size:11px;font-weight:700;letter-spacing:0.5px;">
          Analyse Temps Réel · 30 Caractéristiques
        </span>
        <span style="background:rgba(79,123,255,0.15);border:1px solid rgba(79,123,255,0.4);
            color:#a0bfff;padding:0.3rem 0.9rem;border-radius:20px;
            font-family:'Poppins',sans-serif;font-size:11px;font-weight:700;letter-spacing:0.5px;">
          Score IA Certifié
        </span>
        <span style="background:rgba(255,71,87,0.15);border:1px solid rgba(255,71,87,0.4);
            color:#ff8fa0;padding:0.3rem 0.9rem;border-radius:20px;
            font-family:'Poppins',sans-serif;font-size:11px;font-weight:800;letter-spacing:0.5px;">
          v5.0
        </span>
      </div>
    </div>

    <script>
      // Génère des étoiles aléatoires sur le canvas
      const canvas = document.getElementById('stars');
      const ctx = canvas.getContext('2d');
      function resize() {
        canvas.width  = canvas.offsetWidth;
        canvas.height = canvas.offsetHeight;
        ctx.clearRect(0,0,canvas.width,canvas.height);
        for(let i=0;i<120;i++){
          const x = Math.random()*canvas.width;
          const y = Math.random()*canvas.height;
          const r = Math.random()*1.5+0.3;
          ctx.beginPath();
          ctx.arc(x,y,r,0,Math.PI*2);
          ctx.fillStyle = `rgba(255,255,255,${Math.random()*0.7+0.2})`;
          ctx.fill();
        }
      }
      resize();
    </script>
    """, height=360)

    col_l, col_c, col_r = st.columns([1, 1.2, 1])
    with col_c:

        st.markdown("<br>", unsafe_allow_html=True)

        # ── Afficher erreur OAuth si présente ────────────────────────────────────────
        if st.session_state._oauth_err:
            st.error(f"❌ Erreur Google OAuth : {st.session_state._oauth_err}")
            with st.expander("🔍 Aide au diagnostic", expanded=True):
                st.markdown("""
**Causes fréquentes :**
- **invalid_grant** : le code expire en 60s — recliquez sur le bouton Google.
- **redirect_uri_mismatch** : dans Google Console, l'URI doit être `https://hemerson-trustlink.streamlit.app/oauth2callback`
- **State mismatch** : redémarrez Streamlit et réessayez.
- **Voir le terminal** : les lignes `[OAuth DEBUG]` indiquent l'étape exacte du blocage.
                """)
            st.session_state._oauth_err = None

        # ── Verrou anti-brute-force ──────────────────────────────────────────
        if _locked():
            _secs = int(st.session_state.locked_until - _time.time())
            st.error(f"🔒 Trop de tentatives incorrectes — verrouillé {_secs // 60}min {_secs % 60}s.")
            st.caption("Réessayez dans quelques minutes ou contactez l'administrateur.")
            st.stop()

        # ════════════════════════════════════════════════════════════════════
        # SECTION A ── CONNEXION GOOGLE OAUTH 2.0
        # ════════════════════════════════════════════════════════════════════
        st.markdown("""
        <div style="background:linear-gradient(135deg,#10193d,#0c1228);border:2px solid #3a5adf;
            border-radius:14px;padding:1.4rem 1.6rem;margin-bottom:0.5rem;">
            <div style="color:#b8cfff;font-size:12px;font-weight:800;text-align:center;
                text-transform:uppercase;letter-spacing:1.5px;margin-bottom:1rem;">
                🌐 Utilisateurs — Connexion Google
            </div>
        """, unsafe_allow_html=True)

        if OAUTH_OK:
            _auth_url = _get_auth_url()
            # Bouton Google authentique via HTML natif (pas de rechargement Streamlit)
            st.markdown(f"""
            <a href="{_auth_url}" target="_self"
               style="display:flex;align-items:center;justify-content:center;gap:14px;
                      background:#ffffff;color:#1f1f3d;border:2.5px solid #4f7bff;
                      border-radius:12px;padding:0.9rem 1.5rem;font-family:'Poppins',sans-serif;
                      font-weight:900;font-size:15px;text-decoration:none;
                      box-shadow:0 4px 18px rgba(79,123,255,0.3);text-transform:uppercase;">
                <svg width="22" height="22" viewBox="0 0 48 48" xmlns="http://www.w3.org/2000/svg">
                    <path fill="#EA4335" d="M24 9.5c3.14 0 5.95 1.08 8.17 2.86l6.1-6.1C34.46 3.1 29.52 1 24 1 14.82 1 7.07 6.48 3.64 14.22l7.12 5.53C12.5 13.59 17.79 9.5 24 9.5z"/>
                    <path fill="#4285F4" d="M46.14 24.5c0-1.6-.14-3.13-.4-4.61H24v8.73h12.44c-.54 2.9-2.18 5.36-4.64 7.02l7.12 5.53C43.16 37.3 46.14 31.38 46.14 24.5z"/>
                    <path fill="#FBBC05" d="M10.76 28.25A14.55 14.55 0 0 1 9.5 24c0-1.48.26-2.91.72-4.25L3.1 14.22A23.94 23.94 0 0 0 0 24c0 3.86.92 7.5 2.55 10.72l8.21-6.47z"/>
                    <path fill="#34A853" d="M24 47c5.52 0 10.15-1.83 13.53-4.97l-7.12-5.53C28.6 38.02 26.42 38.5 24 38.5c-6.21 0-11.5-4.09-13.24-9.75l-8.21 6.47C6.07 43.52 14.42 47 24 47z"/>
                </svg>
                Se connecter avec Google
            </a>
            <p style="text-align:center;color:#6a82a8;font-size:11px;font-family:'Poppins',sans-serif;
                margin:0.4rem 0 0.5rem;font-weight:600;">Tout compte Gmail valide est accepté</p>
            """, unsafe_allow_html=True)
        else:
            st.warning("⚠️ Librairie OAuth manquante.")
            st.code("pip install google-auth-oauthlib google-auth", language="bash")

        st.markdown("</div>", unsafe_allow_html=True)

        # ════════════════════════════════════════════════════════════════════
        # SECTION B ── ACCÈS ADMIN (RESTREINT — 1 SEUL COMPTE)
        # ════════════════════════════════════════════════════════════════════
        st.markdown("""
        <div style="height:1px;background:linear-gradient(90deg,transparent,#2a3f6f,transparent);
            margin:1rem 0;"></div>
        <div style="text-align:center;color:#3a5070;font-size:11.5px;font-weight:800;
            text-transform:uppercase;letter-spacing:2px;margin-bottom:0.9rem;">
            ── Accès Administrateur ──
        </div>
        """, unsafe_allow_html=True)

        # Le placeholder ne révèle pas l'email réel
        admin_email_input = st.text_input(
            "🔑 Identifiant",
            placeholder="Identifiant administrateur",
            key="adm_email",
            help="Réservé à l'administrateur système",
        )
        admin_mdp_input = st.text_input(
            "🔒 Mot de passe",
            type="password",
            placeholder="••••••••••••",
            key="adm_mdp",
        )

        if st.button("🔓 ACCÈS ADMIN", use_container_width=True, key="btn_admin"):
            if _locked():
                st.error("🔒 Accès temporairement bloqué.")
            elif not admin_email_input.strip() or not admin_mdp_input:
                st.warning("⚠️ Renseignez l'identifiant et le mot de passe.")
            else:
                _email_try = admin_email_input.strip().lower()
                # Double condition : email ET mot de passe tous les deux valides
                # hmac.compare_digest sur l'email pour éviter l'énumération de comptes
                _email_ok = hmac.compare_digest(_email_try, _ADMIN_EMAIL)
                _mdp_ok   = _verify(admin_mdp_input, st.session_state._admin_hash)
                if _email_ok and _mdp_ok:
                    st.session_state.authenticated  = True
                    st.session_state.user_email     = _ADMIN_EMAIL
                    st.session_state.user_nom       = _ADMIN_NAME
                    st.session_state.user_role      = "admin"
                    st.session_state.user_picture   = ""
                    st.session_state.login_type          = "admin"
                    st.session_state.login_attempts      = 0
                    st.rerun()
                else:
                    _fail()
                    _left = max(0, 5 - st.session_state.login_attempts)
                    # Message intentionnellement vague (pas de confirmation si c'est l'email ou le mdp)
                    st.error(f"❌ Identifiants incorrects. ({_left} tentative(s) restante(s))")

        st.markdown("""
        <div style="text-align:center;color:#2a3a55;font-size:10.5px;font-weight:700;
            margin-top:1.2rem;letter-spacing:0.5px;">
            🔒 OAuth 2.0 · PBKDF2-SHA256 · Anti-brute-force &nbsp;•&nbsp; TrustLink v5.0
        </div>
        """, unsafe_allow_html=True)

    st.stop()

# ═════════════════════════════════════════════════════════════════════════════════
# 🔌 CHARGEMENT DES RESSOURCES
# ═════════════════════════════════════════════════════════════════════════════════
@st.cache_resource
def charger_modele():
    try:
        modele = joblib.load("model.pkl")
        scaler = joblib.load("scaler.pkl")
        return modele, scaler
    except FileNotFoundError:
        st.error("❌ ERREUR: Modèles ML non trouvés!")
        return None, None

modele, scaler = charger_modele()

# ═════════════════════════════════════════════════════════════════════════════════
# 🗂️ SESSION STATE INIT
# ═════════════════════════════════════════════════════════════════════════════════
if "historique" not in st.session_state:
    st.session_state.historique = []
if "critiques" not in st.session_state:
    st.session_state.critiques = set()

# ═════════════════════════════════════════════════════════════════════════════════
# 🎨 STYLING CSS COMPLET
# ═════════════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@500;600&display=swap');

:root {
    --bg-primary: #0a0e27;
    --bg-secondary: #050812;
    --bg-card: #111b3d;
    --bg-card-hover: #192551;
    --bg-accent: #0f1436;
    --border-primary: #2a3f5f;
    --border-secondary: #3a4f6f;
    --text-primary: #ffffff;
    --text-secondary: #e0e7ff;
    --text-muted: #a0aec0;
    --text-subtle: #7c8db5;
    --accent-blue: #4f7bff;
    --accent-blue-light: #6b8aff;
    --accent-red: #ff4757;
    --accent-red-light: #ff6b7a;
    --accent-green: #2ed573;
    --accent-green-light: #4ade80;
    --accent-orange: #ffa502;
    --accent-orange-light: #ffb74d;
    --shadow-primary: rgba(0, 0, 0, 0.4);
    --shadow-accent: rgba(79, 123, 255, 0.2);
    --gradient-primary: linear-gradient(135deg, #0a0e27 0%, #050812 50%, #0f1436 100%);
    --gradient-card: linear-gradient(135deg, #111b3d 0%, #192551 100%);
    --gradient-accent: linear-gradient(135deg, #4f7bff 0%, #00d4ff 100%);
}

* { box-sizing: border-box; margin: 0; padding: 0; }

html, body, [class*="css"], .stApp {
    font-family: 'Poppins', sans-serif !important;
    background: var(--gradient-primary) !important;
    color: var(--text-primary) !important;
    line-height: 1.6 !important;
    font-weight: 400 !important;
}

.main .block-container {
    padding: 2rem 2.5rem !important;
    max-width: 1900px !important;
    margin: 0 auto !important;
}

[data-testid="stHeader"] { display: none !important; }
#MainMenu, footer { display: none !important; }



[data-testid="stSidebar"] {
    background: var(--gradient-card) !important;
    border-right: 3px solid var(--border-primary) !important;
    box-shadow: 4px 0 20px var(--shadow-primary) !important;
}

/* Logo + contenu pas coupé par le header */
[data-testid="stSidebar"] > div:first-child {
    padding-top: 0px !important;
}

/* Contraste texte sidebar */
[data-testid="stSidebar"] p,
[data-testid="stSidebar"] span,
[data-testid="stSidebar"] label,
[data-testid="stSidebar"] div {
    color: #ffffff !important;
}
[data-testid="stSidebar"] .stMarkdown p {
    color: #ffffff !important;
    font-weight: 700 !important;
}
[data-testid="stSidebar"] [data-testid="stMetricValue"] {
    color: #ffffff !important;
    font-weight: 900 !important;
}
[data-testid="stSidebar"] [data-testid="stMetricLabel"] {
    color: #a0bfff !important;
    font-weight: 700 !important;
}
[data-testid="stSidebar"] .stSlider label,
[data-testid="stSidebar"] .stSlider span {
    color: #ffffff !important;
    font-weight: 700 !important;
}

[data-testid="stTabs"] [role="tablist"] {
    border-bottom: none !important;
    gap: 0.7rem !important;
    padding: 0.8rem 0.5rem 1.2rem 0.5rem !important;
    margin-bottom: 1.5rem !important;
    display: flex !important;
    flex-wrap: wrap !important;
    background: linear-gradient(135deg, #0d1228, #0a0e27) !important;
    border-radius: 16px !important;
    border: 1.5px solid #1e2d52 !important;
}

[data-testid="stTabs"] [role="tab"] {
    color: #a0aec0 !important;
    font-weight: 800 !important;
    font-size: 13px !important;
    padding: 0.65rem 1.3rem !important;
    border-radius: 50px !important;
    border: 2px solid #2a3f6f !important;
    background: #0f1a38 !important;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
    letter-spacing: 0.8px !important;
    text-transform: uppercase !important;
    margin: 0.2rem !important;
    box-shadow: 0 2px 8px rgba(0,0,0,0.3) !important;
}

[data-testid="stTabs"] [role="tab"]:hover {
    color: #ffffff !important;
    background: #1a2d5a !important;
    border-color: #4f7bff !important;
    box-shadow: 0 4px 16px rgba(79,123,255,0.35) !important;
    transform: translateY(-2px) !important;
}

[data-testid="stTabs"] [role="tab"][aria-selected="true"] {
    color: #00e5ff !important;
    background: rgba(0,229,255,0.08) !important;
    border-color: #00e5ff !important;
    box-shadow: 0 0 0 2px rgba(0,229,255,0.2), 0 6px 20px rgba(0,229,255,0.3) !important;
    transform: translateY(-1px) !important;
}

.stNumberInput input, .stTextInput input, .stSelectbox select, .stTextArea textarea {
    background: #1a2550 !important;
    border: 3px solid #4f7bff !important;
    color: #ffffff !important;
    border-radius: 12px !important;
    padding: 1rem !important;
    font-size: 16px !important;
    font-weight: 700 !important;
    font-family: 'Poppins', sans-serif !important;
    transition: all 0.3s ease !important;
    caret-color: #4f7bff !important;
}

.stNumberInput input::placeholder, .stTextInput input::placeholder, .stTextArea textarea::placeholder {
    color: #6b82c0 !important;
    font-weight: 600 !important;
    font-style: italic !important;
}

.stNumberInput input:focus, .stTextInput input:focus, .stTextArea textarea:focus {
    border-color: var(--accent-blue) !important;
    box-shadow: 0 0 0 4px rgba(79, 123, 255, 0.15) !important;
    outline: none !important;
}

.stNumberInput label, .stTextInput label, .stSelectbox label, .stTextArea label, .stSlider label {
    color: var(--text-secondary) !important;
    font-weight: 900 !important;
    font-size: 13px !important;
    text-transform: uppercase !important;
    letter-spacing: 1px !important;
    margin-bottom: 0.5rem !important;
}

.stButton > button {
    background: var(--gradient-accent) !important;
    color: white !important;
    border: none !important;
    border-radius: 12px !important;
    padding: 1rem 2.5rem !important;
    font-weight: 900 !important;
    font-size: 15px !important;
    letter-spacing: 1px !important;
    text-transform: uppercase !important;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
    box-shadow: 0 6px 20px rgba(79, 123, 255, 0.4) !important;
}

.stButton > button:hover {
    transform: translateY(-3px) !important;
    box-shadow: 0 12px 32px rgba(79, 123, 255, 0.6) !important;
}

/* ── Zone upload CSV — contraste maximal ────────────────────────────────── */
[data-testid="stFileUploader"] {
    background: #0d1530 !important;
    border: 3px solid #4f7bff !important;
    border-radius: 16px !important;
    padding: 1.2rem 1.5rem !important;
    box-shadow: 0 0 24px rgba(79, 123, 255, 0.2) !important;
}

/* Label "IMPORTER VOTRE FICHIER CSV" — blanc pur, grand, visible */
[data-testid="stFileUploader"] label p,
[data-testid="stFileUploader"] > label,
[data-testid="stFileUploader"] label {
    color: #ffffff !important;
    font-weight: 900 !important;
    font-size: 16px !important;
    text-transform: uppercase !important;
    letter-spacing: 1.5px !important;
    text-shadow: 0 0 12px rgba(79, 123, 255, 0.8) !important;
}

/* Zone de drop intérieure */
[data-testid="stFileUploaderDropzone"] {
    background: #111b3d !important;
    border: 2px dashed #00d4ff !important;
    border-radius: 12px !important;
    padding: 2rem 1.5rem !important;
}

/* Texte "Drag and drop" et "Limit..." */
[data-testid="stFileUploaderDropzoneInstructions"] span,
[data-testid="stFileUploaderDropzoneInstructions"] small,
[data-testid="stFileUploaderDropzoneInstructions"] p,
[data-testid="stFileUploaderDropzoneInstructions"] {
    color: #e0e7ff !important;
    font-size: 14px !important;
    font-weight: 700 !important;
}

/* Bouton "Browse files" — fond bleu vif, texte blanc, très contrasté */
[data-testid="stFileUploaderDropzone"] button {
    background: linear-gradient(135deg, #4f7bff 0%, #00d4ff 100%) !important;
    color: #ffffff !important;
    border: none !important;
    border-radius: 10px !important;
    padding: 0.75rem 2rem !important;
    font-weight: 900 !important;
    font-size: 15px !important;
    letter-spacing: 1px !important;
    text-transform: uppercase !important;
    box-shadow: 0 4px 20px rgba(79, 123, 255, 0.7) !important;
    cursor: pointer !important;
    min-width: 160px !important;
}

[data-testid="stFileUploaderDropzone"] button:hover {
    background: linear-gradient(135deg, #00d4ff 0%, #4f7bff 100%) !important;
    transform: translateY(-2px) !important;
    box-shadow: 0 8px 28px rgba(0, 212, 255, 0.8) !important;
}

[data-testid="stFileUploaderDropzone"] button p,
[data-testid="stFileUploaderDropzone"] button span {
    color: #ffffff !important;
    font-weight: 900 !important;
    font-size: 15px !important;
}

[data-testid="stMetric"] {
    background: var(--gradient-card) !important;
    border: 3px solid var(--border-primary) !important;
    border-radius: 16px !important;
    padding: 2rem !important;
    box-shadow: 0 8px 24px var(--shadow-primary) !important;
    transition: transform 0.3s ease !important;
}

[data-testid="stMetricLabel"] {
    color: var(--text-muted) !important;
    font-size: 13px !important;
    font-weight: 900 !important;
    text-transform: uppercase !important;
    letter-spacing: 1.5px !important;
}

[data-testid="stMetricValue"] {
    color: var(--text-primary) !important;
    font-size: 2.5rem !important;
    font-weight: 900 !important;
}

[data-testid="stAlert"] {
    border-radius: 12px !important;
    border-left: 6px solid var(--accent-blue) !important;
    background: rgba(79, 123, 255, 0.08) !important;
    color: var(--text-primary) !important;
    padding: 1.5rem !important;
    font-weight: 700 !important;
}

[data-testid="stDataFrame"] {
    border: 3px solid var(--border-primary) !important;
    border-radius: 12px !important;
    box-shadow: 0 6px 20px var(--shadow-primary) !important;
}

::-webkit-scrollbar { width: 10px; }
::-webkit-scrollbar-track { background: var(--bg-secondary); border-radius: 6px; }
::-webkit-scrollbar-thumb { background: var(--border-primary); border-radius: 6px; }
::-webkit-scrollbar-thumb:hover { background: var(--accent-blue); }

.card-premium {
    background: var(--gradient-card);
    border: 3px solid var(--border-primary);
    border-radius: 16px;
    padding: 2.5rem;
    margin-bottom: 2.5rem;
    box-shadow: 0 10px 32px var(--shadow-primary);
    transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
}

.card-premium:hover { transform: translateY(-4px); box-shadow: 0 16px 48px var(--shadow-primary); }
.card-title { font-size: 20px; font-weight: 900; color: var(--text-primary); margin-bottom: 0.8rem; text-transform: uppercase; letter-spacing: 1px; }
.card-subtitle { font-size: 15px; color: var(--text-muted); font-weight: 700; line-height: 1.6; }

.badge-premium { display: inline-block; padding: 0.7rem 1.3rem; border-radius: 30px; font-size: 13px; font-weight: 900; text-transform: uppercase; letter-spacing: 1px; border: 3px solid; transition: all 0.3s ease; }
.badge-success { background: rgba(46,213,115,0.1); color: var(--accent-green); border-color: var(--accent-green); }
.badge-danger { background: rgba(255,71,87,0.1); color: var(--accent-red); border-color: var(--accent-red); }
.badge-warning { background: rgba(255,165,2,0.1); color: var(--accent-orange); border-color: var(--accent-orange); }
.badge-info { background: rgba(79,123,255,0.1); color: var(--accent-blue); border-color: var(--accent-blue); }
.badge-critique { background: rgba(255,0,128,0.15); color: #ff0080; border-color: #ff0080; }

.stat-box {
    background: var(--gradient-card);
    border: 3px solid var(--border-primary);
    border-radius: 14px;
    padding: 2rem;
    text-align: center;
    box-shadow: 0 8px 24px var(--shadow-primary);
    transition: all 0.3s ease;
}
.stat-box:hover { transform: translateY(-3px); }
.stat-label { font-size: 12px; color: var(--text-muted); text-transform: uppercase; font-weight: 900; letter-spacing: 1.5px; margin-bottom: 1rem; }
.stat-value { font-size: 2.5rem; font-weight: 900; color: var(--text-primary); line-height: 1.1; }

.progress-bar-premium { width: 100%; height: 12px; background: var(--bg-card-hover); border-radius: 6px; overflow: hidden; margin: 2rem 0; border: 2px solid var(--border-primary); }
.progress-fill { height: 100%; border-radius: 4px; transition: width 0.8s cubic-bezier(0.4, 0, 0.2, 1); }
.progress-success { background: var(--gradient-accent); }
.progress-danger { background: linear-gradient(90deg, #ff4757, #ff6b7a); }
.progress-warning { background: linear-gradient(90deg, #ffa502, #ffb74d); }

.verdict-box-premium { border-radius: 16px; padding: 3rem; border: 4px solid; margin-bottom: 2.5rem; }
.verdict-danger { border-color: var(--accent-red); background: linear-gradient(135deg, rgba(255,71,87,0.08) 0%, rgba(255,71,87,0.02) 100%); }
.verdict-warning { border-color: var(--accent-orange); background: linear-gradient(135deg, rgba(255,165,2,0.08) 0%, rgba(255,165,2,0.02) 100%); }
.verdict-success { border-color: var(--accent-green); background: linear-gradient(135deg, rgba(46,213,115,0.08) 0%, rgba(46,213,115,0.02) 100%); }

.section-divider { height: 2px; background: linear-gradient(90deg, transparent, var(--border-secondary), transparent); margin: 3rem 0; border-radius: 1px; }

@keyframes fadeInUp { from { opacity: 0; transform: translateY(30px); } to { opacity: 1; transform: translateY(0); } }
@keyframes pulse { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.05); } }
@keyframes shimmer { 0% { transform: translateX(-100%); } 100% { transform: translateX(100%); } }
.animate-in { animation: fadeInUp 0.8s cubic-bezier(0.4, 0, 0.2, 1); }
.animate-pulse { animation: pulse 2s infinite; }

.tooltip-container { position: relative; display: inline-block; cursor: help; }
.tooltip-text {
    visibility: hidden; width: 220px; background: #111b3d; color: #e0e7ff;
    text-align: left; border-radius: 8px; padding: 0.8rem 1rem;
    position: absolute; z-index: 999; bottom: 125%; left: 50%; margin-left: -110px;
    opacity: 0; transition: opacity 0.3s; font-size: 12px; font-weight: 600;
    border: 2px solid #2a3f5f; box-shadow: 0 8px 24px rgba(0,0,0,0.4); line-height: 1.5;
}
.tooltip-container:hover .tooltip-text { visibility: visible; opacity: 1; }

.grade-A { color: #2ed573; font-weight: 900; font-size: 3rem; }
.grade-B { color: #4f7bff; font-weight: 900; font-size: 3rem; }
.grade-C { color: #ffa502; font-weight: 900; font-size: 3rem; }
.grade-D { color: #ff4757; font-weight: 900; font-size: 3rem; }

/* Slider styling */
.stSlider [data-baseweb="slider"] { padding: 0.5rem 0 !important; }
</style>
""", unsafe_allow_html=True)

# ── Bouton hamburger custom — remplace la flèche native Streamlit ─────────────
# Cacher la flèche native
st.markdown("""
<style>
[data-testid="stSidebarCollapsedControl"] { display: none !important; }
[data-testid="stSidebarCollapseButton"] { display: none !important; }
</style>
""", unsafe_allow_html=True)

# Bouton hamburger dans components.html pour accéder à window.parent
import streamlit.components.v1 as _comp_sidebar
_comp_sidebar.html("""
<style>
  body { margin:0; background:transparent; }
  #hbtn {
    position: fixed;
    top: 10px;
    left: 10px;
    z-index: 999999;
    width: 48px;
    height: 48px;
    border-radius: 50%;
    background: rgba(20,25,50,0.92);
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 5px;
    cursor: pointer;
    box-shadow: 0 2px 14px rgba(0,0,0,0.6);
    border: 1.5px solid rgba(255,255,255,0.2);
  }
  #hbtn span {
    display: block;
    width: 22px;
    height: 2.5px;
    background: #e0e7ff;
    border-radius: 2px;
  }
</style>
<div id="hbtn" onclick="toggleSidebar()">
  <span></span><span></span><span></span>
</div>
<script>
function toggleSidebar() {
  var p = window.parent.document;
  // Sidebar ouvert → cherche bouton fermer
  var btnClose = p.querySelector('[data-testid="stSidebarCollapseButton"] button');
  if (btnClose) { btnClose.click(); return; }
  // Sidebar fermé → cherche bouton ouvrir
  var btnOpen = p.querySelector('[data-testid="stSidebarCollapsedControl"] button');
  if (btnOpen) { btnOpen.click(); return; }
  // Fallback : toggle class sur sidebar
  var sb = p.querySelector('[data-testid="stSidebar"]');
  if (sb) { sb.style.display = sb.style.display === 'none' ? '' : 'none'; }
}
</script>
""", height=68, scrolling=False)

# ═════════════════════════════════════════════════════════════════════════════════
# 📊 TOOLTIPS V1-V28
# ═════════════════════════════════════════════════════════════════════════════════
TOOLTIPS_V = {
    1: "Distance temporelle de la transaction par rapport au centroïde PCA",
    2: "Composante PCA 2 — anomalie sur le volume",
    3: "Composante PCA 3 — comportement du commerçant",
    4: "Composante PCA 4 — fréquence d'utilisation",
    5: "Composante PCA 5 — localisation géographique encodée",
    6: "Composante PCA 6 — historique du titulaire",
    7: "Composante PCA 7 — heure normalisée de la journée",
    8: "Composante PCA 8 — type de terminal",
    9: "Composante PCA 9 — secteur commercial",
    10: "Composante PCA 10 — montant relatif moyen",
    11: "Composante PCA 11 — ratio transactions récentes",
    12: "Composante PCA 12 — distance au dernier achat",
    13: "Composante PCA 13 — changement de pays",
    14: "Composante PCA 14 — score de vieillissement du compte",
    15: "Composante PCA 15 — indicateur de fraude passée",
    16: "Composante PCA 16 — cohérence des achats",
    17: "Composante PCA 17 — réseau de transactions liées",
    18: "Composante PCA 18 — vitesse inter-transactions",
    19: "Composante PCA 19 — anomalie de montant par catégorie",
    20: "Composante PCA 20 — profil démographique encodé",
    21: "Composante PCA 21 — indicateur d'activité nocturne",
    22: "Composante PCA 22 — cohérence du canal de paiement",
    23: "Composante PCA 23 — volatilité du solde",
    24: "Composante PCA 24 — transactions refusées récentes",
    25: "Composante PCA 25 — écart au budget habituel",
    26: "Composante PCA 26 — ratio achat en ligne / physique",
    27: "Composante PCA 27 — indicateur multi-comptes",
    28: "Composante PCA 28 — signature comportementale résiduelle",
}

# ═════════════════════════════════════════════════════════════════════════════════
# 📊 SIDEBAR
# ═════════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    components.html("""
    <div style="padding:1rem 0.75rem 1rem; border-bottom:4px solid #3a4f6f; margin-bottom:1rem; font-family:'Poppins',sans-serif; overflow:hidden; box-sizing:border-box;">
        <div style="display:flex; align-items:center; gap:0.5rem; margin-bottom:0.75rem;">
            <div style="display:flex; align-items:center; gap:0.4rem; flex-shrink:0; margin-right:auto;">
            <img src="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAAkGBxESEhUTEBIWFRUWFxUbFxcVGRceFRsWGxcdHRkXGRgeKDQkHh8nIBkZJTMjJiwtMDAvHiI0OD8uNyktMS0BCgoKDg0OGBAQGi0lHyUtLS8tLS0tLy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLf/AABEIAMgAyAMBEQACEQEDEQH/xAAbAAEAAgMBAQAAAAAAAAAAAAAABAUBAgMGB//EAEwQAAIAAwMFDAYJAwMBCQEAAAECAAMRBBIhBSIxQdEGExUyUVJTYXGBkZIWQkNzk7EHFCNygqHBwtIzYvCio7LiJCU0NVRkg+HxF//EABsBAQACAwEBAAAAAAAAAAAAAAABAgMEBQYH/8QAMhEAAgECBQMEAQMEAQUAAAAAAAECAwQREhMhUQUVMQYUQVIyIjRhI0JxkSQWJTNigf/aAAwDAQACEQMRAD8A+4wAgBACAEAIAQAgBACAMQAiNwIkbCA2MwAgBACAEAIAQAgBACAEAcZtoVdJ0aeSGBGJHGVJeoTG61luw8QKROUjMOE05k34U3ZDAZhwmnMm/Cm7IYDMOE05k34U3ZDAZhwmnMm/Cm7IYDMOE05k34U3ZDAZhwmnMm/Cm7IYDMOE05k34U3ZDAZhwmnMm/Cm7IYDMOE05k34U3ZDKycxxn5blIKsJgHKZcwfpE5WRmNZeX5LGgEyvJvb1py6IZGRnRI4UTmTfhTNkRlZOZDhNOZN+FN2QwGYcJpzJvwpuyGAzDhNOZN+FN2QwGYcJpzJvwpuyGAzDhNOZN+FN2QwGYcJpzJvwpuyGAzDhNOZN+FN2QwGYcJpzJvwpuyGAzDhNOZN+FN2QwGYwcqS9YmL1tLdR4kUhlGYkyrQraDp0ckQWINnlCY7FsVQgAar9A149gIp39UWZVFpFSwgBACAEAIAQAgBAHG0zgiliaACsPJHgh2GzFjvswY+op9UfyP5aO2zZCJFtsgmDkYcVhpU/wCatcQngGjnk+0FgVfB1NGGqvKOo6YMlE6IJEAIAQAgBACAEAIAQBV2iUJbqVwVyQRqD0LXh2gGvdFkVOuSva+8/YkGET4qWEAIAQAgBACAEAIAq532s0J6iUZus+qv69w5Ystir3LOKk+DMCStyktxhOGgZr/c1N+E/kWiy32KssEaoipY2gBACAEAIAQAgBACAIGVfZ+8/Y8SirGS/ae8/YsH8BE+KlhEgQAgBACAEAIAjW60CWhY6hoGk9Q64lLEhs1ydZyiZ3GOcx/uOnuGjsEGES4gkQBpMQMCCKgih7IAg5Lci9KY1KGmOkr6p8PzBiZERLGIJEAIAQAgBAGCwEAZgBAEDKvsvefsaJRVjJftPefsWD+AifFSwiQIAQAgBACAMQBWzPtZwX1ZdGb73qD5nuWLLYqyzipYQAgBAFblAXHSaNHEfsJzT3H/AJGJRVlipqIgsZgBACAMEwBwM4nBBXr1CAOVpsZZCLxvEYHUD2QBpki1l1o2DLgw6xAFhAEDKvsvefsaJRVjJftPefsWD+AifFSwiQIAQAgBACAI1ttARCx1DVp7uuBBpk2zlEzuOxvP946u4UHdEsImRBIgBACAOc+UHUqwqCCCOowRDIeS5poZbnOQ3T18jd4oYlhFhEEiAOMyeBgMTyCANRKLcc/hGjvgCsypl6XJDCXdmMoIuK2cHoWVSADSoV+8UAJMAW8pwygggggEEaCDrEAVtslGXNWamhsHHXqaGwwIe6PLrykP1WXv8wEXkFcAeUgadGEYqk2vBvWltGrL+q8EdUacZckzwA5fEDQDvbYRmh4NOuoqX6Sdkv2nvP2LB/BjRPipYRIEAIAQAgBAFY32s6nqS6E8hf1R3cbyxYqWcVLCAEAaTZoUVJpAHBbTiKqQDoJ/zCAJUAVuUVuMs4aBmv8Ac1N+E/kTFkVZNM4AVJipY0zm/tH+o7IAjNbpaM0tVZmVS7XRjhSgJJGLVw1ZrYikAUE3KdotuZZ1aUlHq5JGcrS8xnTGWSpcjSCChzhUQBc5NyJLlgFxeYEtjiFLFWaldNXQPU+tU4QDOttysiZozmOhVxJ7B+ujriGzLCjm8kZLFOnGs5ii8xTnfiYaOxfExXDHyXzQpvCO/wDJaWazJLUKihQNQGEWwS8GGU3J7kbKns/efseLox/JnJftPefsWIfwET4qWESBACANWYDTAERrYWNJQvHl9Ud8AaWhmly2d2vECpA0U5BBENnXJsgogB4xzm+8cTs7AIlsIlxBJisARntFTdQVPLqHaYAwJQWrzGBoCSWwVQNJ6u2ANkdJyVRgynQymoqDy9REAZsswnNbjLgdsPkGtptEsEI7LV6gKSM7DEAa8IjMsS2nJrFLZEbJNBeRsXlmlTpK+qfCleusWkY0Ve6HK09JwkyKVaXRQTnM71usgocFuUY+rfDEUGMFixyXYnokycW30KyNW5VlJqA4Wow1UJ144mA2O02fIsyAAKijQqgAY6gBEN4eS8YSlsiHetFo0fZS+UjPI6lOj8XhFfJmShT87sn2LJ0uUM0YnSxxY9pMWUcDFKrKRNiTGIAgZV9l7z9jRKKsZL9p7z9iwfwET4qWESDBMARJltxuyxebq0DtMAaPZ8C09xQYkVogHWYA4WnLciU6SgbzFit2XQ3aXb1RXVfUmmIGOgGAJNpz3RNQz27Acwd7Y/gMSVZJl4VHJo7IgsazbSq6TjyDTEYk4M5XGfjZq8g0ntMSQRcq5XlWVDXjBbwQV4t9VvtQGi1YVPbpgCmk2e0Wz+ozLKKXcHzSCaTFa4aMxUuhPqNLDLxoAvrHISzS7t8kCpq12vXgoAHcBrOkmBKWJEW1zJzVkKAujfWGFP7R63bo6zFMW/BnUIwX6il3S2FZM6xzKlmM8BnbFjeRvAdQwjHUWElgblrVc6VSGHwegtouPLmjQaI3fxD41H4o2Vucp7MsJk9VW8xAHKYoy0U2VLZRmzsLMub0jcX8PO7sOuK4t/iZ1TjDep/okWLJCob7kzJnObV90aB3d9YlR5KyrN7LZFlSLGEQBmAEAQMq+y95+xolFWMl+095+xYP4CJ0VLEWbbADdUFm5BEg0Fld8ZrUHNX9TAEa25as8hRQipAKqMKg6MdAwBOOpWOowHkqpz2yeWVSM1pgBSolEErvbM5qJgWkxHTA9WgwGxZ2PIElFo4E0VvfaAGhC3Qcdd0KCddK6zD+B4NpeUERTNY4zDmjXd9RQNJNMaDWxhJ4bFqdNz3RgG0TtH2ScpA3wjqXQv4q9kUTbM2FOHnco50r6tlGTdLETJUwNUkklSrVx10rGPxJG5F6ttNv+3A9LlQzt7DWci8CGphnLzRXAVw/+tIznL3Kzc/uf3kX5zBnxOAoReWjhzWj4BKmgqUDHGGAJtpymFO9yVvvTBV0AdeoDt7qxVvgzRovzLZGknJbOb1pN48wcQdvOPbh1CISx/Il1Yx2p/7LYCmiLmBts8vu9FEs7c20yfzan6xiqnQ6fjmklwWNstquhlS1MxyKELoU8rNoX59UXUsPBqujvjJ4Ij5NsRnY2k3mUkGWMJYI6vW5cerARLjj+Q1ktof/AEv1UDREmJvE2gQIAQAgBAEDKvsvefsaJRVkexWtVMwaW3zADTxFg/gIk7zMfjm6OaunvMR8lg9pkySiFghc0UcprQVPWSBjrIEAUZtdrtAaXQS2CMGVGYXZqzPWmihAZKMlKVxqaQB1yLubMtzMnkM5CiqsaNhVwwwBF8u1P7jhQKABcT7VKkriVUDAAUAHIBsiGy0KbkU1rtE60sJSAy0YG8zYNc10Xr0Z1OyEX8mRxhD8ty3sWTJcvEAs9MXbFuzqHUKCGG+JWVVvb4J0SYzyu63MtFim8k653TEZdkYan5JnSs3jRqw5LydaVkglzRdXadUZWzQjTlLwQws+0aaypf8AuN3er349Qivky/oprlllZLGksURaD8yeUnWesxZLDwYZTlPdkiJKiAIWVMmS7QlyaKrVWwJBqpqMR1xWUcxlo150pZoM72azJLUKihQNAAwiUsPBSc3J4yIdsG9OJo4rUEzq5r/oe7kiyWJjexYq1REFjaAEAIAQAgCBlX2XvP2NEoqyuyBMuTZ0tqYvVTrOYtR/nXEsI2yxMn37qhyC0tpZlhqc2bLmEaBdJYMdZ5VFaljnk/cvLQq0xiXQUBVmGOhnrpq91Cw517nNUC6tVrSWCXYADTUxDeHktGDk8EV31mfO/pLcXnuD/pXAnvoO2K4t+DMoQjvLzwGssuRntWZM0KWxYk+qg0L3U64soFJ129lsiZk6zFQWfjti1NA5FHUNp1xZmFE2IJMQBS7qMkvaZSrLYK6zJbqW0VVgdsUqRxNq0rqjPGXgk2TJgUh5h3yZzjoH3V0L8+UmJSMc6ze0dkWIixhMwAgBACAEAaugIIIqDpGqAKyW5kG69TLOCMfV/sb9D+um3kr4LRWroiuGBOJmBIgBACAIGVfZe8/Y0SirK95BImOnHSZUeRYlhFoLclwOxoCK46uWsUMii2Qfr02dhZ1ovSPUL3DS3dQdcVxb8GZU4Q3m9+DvZslIpDzCZjjQzaAf7V0Dt09cSo8lZVm9orBG1ot4BuSxffmjV1sfVH+YxdIwSkzay2Mg35hvP/pUcij9df5Qf8DAnRBIgDEAIB/wIAQI8GYEiAEAIAQAgDSYgYUIqDgQdEMRgVxs8yVjKz06MnOH3CfkfGLeSvgk2W3o+ANGGlWwYdoiGiUyXEEiAEAQMq+y95+xolFWefm7o5cqZNkjj3wTUNdUFFpW6Ce75RiqVlB4Nm1Qt8/6mbSMo2KoadOMxtIrLmBAf7Up+ZqeuMSr0+TM4VcMIxwRMn7rbKozSzHkCP8AqIsrmlyYHbVeCL6QSZn9WeUXmy0m173u/KnbE+6pL5I9rWfwTLPugsKCiPQdUuZ48XTD3NPkn2tTg6+lNk6Q/DmfxiPc0+R7apwPSiydIfhzP4w9zT5HtavA9KLJ0h+HM/jD3NPke2q8GfSiydIfhzP4w9zS5HtqvA9KLJ0h+HM/jEe6pcj2tXgelFk6Q/Dmfxifc0+R7apwPSiydIfhzP4w9zT5HtqvBj0psnSH4cz+MPc0+R7arwPSmydIfhzP4w9zT5HtqvA9KbJ0h+HM/jD3NPke1q8D0osnSHyTP4w9zT5HtqvA9KbJ0h+HM/jD3NNfI9tV4HpRZOkPkmfxiPc0uR7WrwZ9KLJ0h+HM/jE+5pcj2tXgx6U2TpD8OZ/GHuKXI9tV4I9qy5YJlLzmo0EJNDDsIFREq6pr5DtanBGG6GXL4k/fByOkwN5guPeO+Jd1TfyQrSpwS7PuuszDOLKeQo/6AxV3FLkn21Xg7elFk6Q+SZ/GHuaXI9rV4OE7LtnnTJUuXMq94tQq4wCMCRUDlEZaVWEvBiqUpx8nyPdxaXl5SnMpoczvFxY0bxNzOhZ/jiMm255zqgahavbgK0A1k0oBrNI1IxxeBuOphEkTWmhbwdbpcoLzKr1ABNVY4aYs6eBRVUzeWk84kqPtJaUDoWJmCqlRXOBHJthpNjWSOdmac5ADKtUdxemIM1VvVxOGAwr8ojTZLqxMpv7GiAnBNJUVLpeAFTjhjhqxhpMasTks6edAPqax7RC6eKgmCgydRHOdbZqtdNa0BwNRQ6CCMCIq4slTTJGTpsyaXALZi3iFUsxF5VwX8UWjAiU0aibONLuIYkKCVDEVIvXa1pgcdGBxidMjVRuotJrQVpdxDJQ3q3bprRq3TSldERpsnViay2tDBSqk3qUAZb2cKrVa1FRorphpyGrE2cWkUza1KgXWU1vcU4HQccdGETpMjWidHSdQsrKQGlqM9KsXDUuY5wqrDD9DRpMjWicWecKDXVwc5LouKrNV60FL4rXRBwZOqiPMt81WKmtRpEUcWXU0drHay4dnmXAgFcCTiaaIsoYlZVEbzmnKWFVNylSHXQaUehNbucuNNcS6eBVVUZtJno8xKqxllg110PF4xArU014Ya6REqe5MaqaMJNmGUswMTea6oUE51QLpOpscBE6ew1FiY3yd2moGayFdDHFgaCl09lDWI05E6sTP/aaE0wGu8uOZezcc7NxwrhDTkhqxNd8n4DAZt7F0F0YYvU5nGXjU0iGmxqoiz8pzEJVqhlJBB0gjVFGsCyliTtwU93ygjE1N19PJSN2zSxZpXreCIX0hj/vGd/8AH/wWJuvySIs/BRyJgVgSocc03qHykGNNNJ4m5L+GWbZecsGaWjEMGFb+H2ay6aeai4nGorWMmozHprkyd0EwvfKISHkOK3zRpK3V9apqNNaw1GNNHKTll1VFuKVQOuN81DoVYVrmihJotMYhVP4JcEd7Bl666GZLVlUyiKXry72gSq4jEhRp1xMav8ESppmsndBMQLdRAw3urC/eYJLaUoOdhmORm0MNQh00Q52UZpmGYrurEAVDvWnJeJJ1csVc2ZFBGbPlF1Llxvu+LdbfC5qLysMQQfUGuGZkOKOsvK5FykqXVAyg5/8ATa9VDnaM9hXT1xOdkZEbLluYCl1EAlvKZFF6g3u9QYmuJdiYZ2NNGZeW3UCiJeogZs6rCWl1AcaaKaKaBE6jI00a2XLc2WVKhaqJYGnQhJGvXWIVRkumjcZcmVJKhs+U4vNMYhpd67iWr67YdcS6jIVNHOxZZmSgAoFAZpOLAnfAgIqpBH9NaUiM5MqaxODZQm32dXdSxxuu9TyVJNT3mKuZbIsDazZQZb99Vm75S9vhfSDWtVIMSpshwXJJfL00o6FV+0rUi8MDdwoDTC4AKjARbUZXTRu26CZ9qRLQGaZpYi/pmJdf1sdJIBqASYajbCppEfJ+Vnkr9mihjdq5vkkK4cVFbulRqiFNpEummzez5aaWaypaIL1aKX5jKcb1Rg50HkiVUZDppmHy1MJBoDQsReLsc5AmliToEHUYVNI3l5dcMXCKGZLrlTMBbFTWobA1QHNprhqDTK2dNLMzHSxJOJOnrNSe+MTxZkisD030b/8Ajk+6/wAo3LT8mal6/wBKPbWjJcu1TppugUYXnugtxFoorGn1rqUbWKSWMmaVFzx2NxuMsvNPi22PHy61cN+Tb3x8mfQyy80+LbYr3q45G49DLLzT4tth3q45G49DLLzT5m2w73c8jcehll5p8W2w71c8jcx6GWXmnzNth3q45IwY9C7LzT5m2w71cck7j0MsvNPi22Hernkbj0MsvNPmbbDvVxyNx6F2XmnzNth3q45G/Jn0MsvNPmbbDvVzyNzHoZZeafM22I71c8jcehll5p8zbYnvVzyNx6GWXmnzNth3q55Bn0MsvNPmbbDvVzyNx6GWXmnzNth3q45G5j0MsvNPmbbDvNxyNx6GWXmnzNth3m55G49DLLzT5m2w7zcchYj0LsvNPmbbDvVxyN+TPoZZeafM22Hernkbj0MsvNPi22Hern7Awdxll5p8W2xaPW7lfJG5rZsmy7JOlG6DeYhXugNxGqpp/mHVHsOi9RheQae0katZy2xLLIAzH65jfJY8z6keNyzJQ8FpHmzOIEiAEWUW/CIbS8iDi08MBihEuLXlDFCChJ+EMTERg8fA2MxbSn5Sf+iM0eTEVcWngycUxEqEn4RDaXkRLhJeUTjj4MxCg5fisRjyItpT+rIzIxFXGS2aGK8mYtpz4f8AoZlyIq4yXlE4r4ERg34GPyIvpT4f+iMy5EUf8k7CAEVJEAVe6AZidUxfkY9J6af/ACUa9fwZyBxH943yEV9R/uWKHgs486ZxAkQB4/6SJ7pKlFGZSZhBukj1THt/RdvCtcSU1ijjdXm4wWBx3OWlzkuexdiwFooxJqKLhjGTqtvTj1lU4rbEm1m5WmPyeWyHujmyJyu7s6aHUknNOsdY0/8A7Hses+n6Fza4U44SS2ORZ3s6db9XgvvpCt7XpDSZhCtLYgqxAIqKHCPPekLCDVeNWOLRu9Vryxg4vZk7KGWJsjJlmdCb8xJKlziRWXUntwjndN6bRuurShU8J+DauriVK1Tj5POZPsb2mU0z63SeC1JTNnNTRnEjTHqru4haVtJ2/wDT5OXSputDMp/qPYbjVtyB0tam6KFGZlLdanGvJ+ceI9QqxqVYSttsXudmx14waqHj52V5lrtN2dP3mWSwxrdUCtBSox6zHt6FhS6fYqpRp55YHGlXnWruNSWCLGxZOyhInXrK5nygRiHW466wQWwOkVjlX91066tP68Mk/wDBtW9KvTq/oeMST9JNpmI8i47LVZlbpI1rGD0Ta0arrOSxwLdYqShlwZByRkK12iSk0Wq6HBIDO9RjT9I6F91a2tq7paHgxUbWpOCk6h6LJuTJ9ms1p32dvhKOVIZjdoh1mPK3l5SvL2nlp5Vj4OjRoyo0JYvE8RkOXarVNMqVPYMEL1Z3pQFRqrzhH0DqU7Lp9GM501ukcO1jVryaTJUvLNssE8pOdnCkX0LFlZDrQnqjQuOmWPV7J1qKwfwZqVxWta2So9j0O77Lk2UJaSWuiYpYsNJGFAD3/KOB6S6RRrVak6qxy+Eb3VbqcIxUfDKGTkqbMky5tmte+TjdLSla66k6cS2rsj0E7+jTqujcUMsOfJpRt5OOenPc91uXNq3m7bFImKxAJKkslBQmmvSO6PnfXFae5btX+k71nqaf9TyW8cXY2vgzFSRAFXug4ie8X5GPRem/3SNev4M5A4j+8b5CHqT90xQ8FnHnTOIEiAPGfSd/Rk+8P/Ax730N+4kcPrX/AI0RtzP/AJTaOy0f8Iy9YX/fF/km22szzO57In1rfwv9RJasnWbxqp7dkes6v1V2NWg3+L8nKs7fWhNLyiunWiYVWW+iXfCg6VqcV8RHUtbejFVLil/ejWq1JNRpy+D6KtrsqZOsqWsEpMky6CmsIuvUY+Y0ba7q9TnO18pno51KULdKp8lE+5KVOkm0WOeSgDm7NArm1qLw0aNYj09P1FXo3Ctrqli+Tmvp8JwdSnPA6/R5lebvrSWZml70zgHEqVK6Oo3tEafq/plLLCtBYSZm6TcVG3GTxSOlosWTrfOpImPKmuGbADe2Os3Tr14U1xFvedT6XbKVaOaBM6Vtczai8GUGUrPPydPok3OChgy1AIxwZe7RHoKNS36vZuU4YbGhJTtK6UWXX0izb/1VyKFpbGnJW4aRxfRMFTncRXwbfWXm0znkLcnLnyJc02m4WBN2gwxI5eqL9S9R1be5lCNDHD5IodPhOmm5np7LkpbLYrRLWZvlVmtXkrLpTT/bHkqt7K86hCpKGXFnVjTVO3cE8TyP0cuBbCSQPsJmn78qPZ+saU52lNQWOxyOkzUKksxx+kG0o9qYoQwEtVJGIJxP6xn9M0Klt05urtszH1GcKlwlA9Rl+dYlkyrPbQ19JSEFRnDC7UH8JwjynSKV/r1K9p4x3Opdyo5YwqnnstblN6kfWZM6/LopAYUajEUIIwOnqj1HTfUDurhWtxSwZzbmxVOGpCR6D6OsqTZqTZc1i29FLrHTRgc0nqu/nHlPWXT6NrXjKn/cdPpNac6eEj2EeKOsZiCRAFXug4ie8X5GPR+m/wB0jXr+BkA5j+8b5CHqRf8AJYoeC0jzpnEQSIApN0+QvriIu+XLrXq3a1wpyiO/0PrPbajllzYmleWnuI5cTTJm57ebJMs2+Xr4mZ12lL4porq7Ym8637i9V1lw/gijaadHSxOO5fct9Td332/fULS7SlDXlMZ+ueoO5RgsuXKVsrH2+OD8kbLu4lLRNM1Jm9luMLtQW52kRu9K9XVbK30XHMv8mG56XGtPPjgWk3c9Keyy7LNJYS0RQ4wYFVpeGmn5xyKPWqtG7dzT2x+DbqWkZ0lTkedTcDMWoW1Zh0i4RXtzqGPUf9a05fqlRTlycx9He6Utj0G53c5Ksl4oSztQMx5B6qjUI811jrtbqE1J7JeEdG1s40I4LyU+U9waPM3yRNMqprdK1AP9uIIjs2PrCVGiqVaGY06vSU5ucXgbWPcKl8PaZpm0IJFKBqamNcR1QvfWM50XSoQyotQ6XGM883iWG6jcz9caWd9uXAw4ta1p1jkjndD9Rvprm8mbMZbywVxhv4KT/wDnZ/8AU/7f/VHf/wCuk93RRpdl/wDYt8iblfq8uem+39/ULW7Smaw5TXjRwep+oVeV6dVU8uU3reydKDinjiVA+jv/ANz/ALf/AFR3l67/AEpOljgaPZflSLLJW4mTKdZkxjNZTUAii11EiprSOT1P1dXu6bpwWVG1b9Lp0nme7LHdFuelWtRfJV1rdddIrqI1iOd0frtXp0247p+UbF3ZxuIpM89L3AzALjWqqVrduGnhej0j9aU086orMc/s7xwc9j1GQ8jyrLL3uVXE1ZjxmY6zHj+p9Tq31V1Kh1be3jRjliWMc0zmYqSIAq90HET3i/Ix6P01+6Rr1/BGvtZZrhwd7c1qBW6eWnJT5R6LrfSndxUqf5L45MVKeXyWAyrZz7eX3uo/WPGS6ZcqTWU2NWBnhSz9PK86bYp225+o1Y8jhSz9PK86bYdtufqNWPI4Us/TyvOm2Hbbn6jVjyOFLP08rzpth225+o1Y8jhSz9PK86bYdtufqNWPI4Us/TyvOm2Hbbn6jVjyOFLP08rzpth225+o1Y8jhSz9PK86bYdtufqNWPI4Us/TyvOm2Hbbn6jVjyOFLP08rzpth225+o1Y8jhSz9PK86bYdtufqNWPI4Us/TyvOm2Hbbn6jVjyOFLP08rzpth225+o1Y8jhSz9PK86bYdtufqNWPI4Us/TyvOm2Hbbn6jVjyOFLP08rzpth225+o1Y8jhSz9PK86bYdtufqNWPI4Us/TyvOm2Hbbn6jVjyOFLP08rzpth225+o1Y8jhSz9PK86bYdtufqNWPI4Us/TyvOm2J7Zc/UaseTByrZx7aX3Op/WJXS7l/2jVjyV5drXNQIDvaGtSKXjy05KfOPadD6U7RZ6n5P44NerUzHsZ9mR+OoPbHoDGQzkOzdEPE7YZURghwFZuiHidsMq4JHAVm6IeJ2wyrgDgKzdEPE7YZVwBwFZuiHidsMq4A4Cs3RDxO2GVcAcBWboh4nbDKuAOArN0Q8TthlXAHAVm6IeJ2wyrgDgKzdEPE7YZVwBwFZuiHidsMq4A4Cs3RDxO2GVcAcBWboh4nbDKuAOArN0Q8TthlXAHAVm6IeJ2wyrgDgKzdEPE7YZVwBwFZuiHidsMq4A4Cs3RDxO2GVcAcBWboh4nbDKuAOArN0Q8TthlXAHAVm6IeJ2wyrgDgKzdEPE7YjKgZGQ7N0Q8TtiUkgSpFmROIoHZE4jA7wAgBACAEAIAQAgBACAEAIAQAgBACAEAIAQAgBACAEAIAQB/9k="
                 style="
                    display:block;
                    width:34px;
                    height:34px;
                    object-fit:contain;
                    border-radius:5px;
                    box-shadow:0 2px 8px rgba(0,0,0,0.5);
                    border:2px solid #3a4f6f;
                    flex-shrink:0;
                 " />
            <div style="font-size:8px;color:#5a6a85;font-weight:700;
                text-transform:uppercase;letter-spacing:1px;">INSSEDS</div>
            </div>
        </div>
        <div style="text-align:center;">
            <div style="font-size:48px; margin-bottom:0.6rem; filter:drop-shadow(0 0 12px rgba(79,123,255,0.4));">🛡️</div>
            <h1 style="font-size:24px; font-weight:900; margin:0; color:#ffffff; text-transform:uppercase; letter-spacing:-0.02em;">HEMERSON</h1>
            <h2 style="font-size:18px; font-weight:900; margin:0.2rem 0 0; background:linear-gradient(135deg,#4f7bff,#00d4ff); -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text; text-transform:uppercase; letter-spacing:0.08em;">TRUSTLINK</h2>
            <p style="font-size:11px; color:#a0aec0; margin:0.6rem 0 0; text-transform:uppercase; letter-spacing:1px; font-weight:800;">🧠 DÉTECTION FRAUDE IA<br><span style="color:#4f7bff;">MACHINE LEARNING</span></p>
        </div>
    </div>
    """, height=280)

    # ── Horloge temps réel ──────────────────────────────────────────────────────
    st.markdown("### ⏱️ HEURE EN TEMPS RÉEL")
    clock_placeholder = st.empty()

    st.markdown("### 📈 STATISTIQUES SESSION")

    total = len(st.session_state.historique)
    fraudes_s = sum(1 for h in st.session_state.historique if h["verdict"] == "FRAUDE")
    suspects_s = sum(1 for h in st.session_state.historique if h["verdict"] == "SUSPECT")
    saines_s = total - fraudes_s - suspects_s

    col1, col2 = st.columns(2)
    col1.metric("📊 TOTAL", total)
    col2.metric("🚨 FRAUDES", fraudes_s)
    col1.metric("⚠️ SUSPECTS", suspects_s)
    col2.metric("✅ SAINES", saines_s)

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    # ── Seuils personnalisables ─────────────────────────────────────────────────
    st.markdown("### 🎯 SEUILS PERSONNALISABLES")
    seuil_suspect = st.slider("⚠️ Seuil SUSPECT (%)", min_value=20, max_value=70, value=50, step=5)
    seuil_fraude = st.slider("🚨 Seuil FRAUDE (%)", min_value=seuil_suspect + 5, max_value=95, value=75, step=5)
    st.markdown(f"""
    <div style="background:linear-gradient(135deg,#0d1f3c,#112244);border:1.5px solid #2a4a7f;
        border-radius:8px;padding:0.5rem 0.75rem;margin-top:0.2rem;">
        <span style="color:#2ed573;font-weight:800;font-size:12px;">✅ Saine</span>
        <span style="color:#e0e8ff;font-weight:700;font-size:12px;"> &lt; {seuil_suspect}%</span>
        <span style="color:#5a7aaa;font-size:12px;"> &nbsp;│&nbsp; </span>
        <span style="color:#ffa502;font-weight:800;font-size:12px;">⚠️ Suspect</span>
        <span style="color:#e0e8ff;font-weight:700;font-size:12px;"> {seuil_suspect}–{seuil_fraude}%</span>
        <span style="color:#5a7aaa;font-size:12px;"> &nbsp;│&nbsp; </span>
        <span style="color:#ff4757;font-weight:800;font-size:12px;">🚨 Fraude</span>
        <span style="color:#e0e8ff;font-weight:700;font-size:12px;"> &gt; {seuil_fraude}%</span>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    if total > 0:
        taux = round(fraudes_s / total * 100, 1)
        couleur_taux = "🔴" if taux > 20 else "🟠" if taux > 5 else "🟢"
        st.markdown(f"""
        <div class="card-premium">
            <div class="stat-label">🎯 TAUX GLOBAL</div>
            <div style="font-size:32px; font-weight:900; color:#ffffff; margin:0.8rem 0;">{couleur_taux} {taux}%</div>
            <div class="progress-bar-premium">
                <div class="progress-fill progress-danger" style="width:{min(taux,100)}%;"></div>
            </div>
            <div style="font-size:11px; color:#a0aec0; margin-top:0.5rem;">{total} transaction(s) analysée(s)</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    # ── Carte utilisateur connecté ──────────────────────────────────────────
    _sb_role_colors = {"admin": "#ff4757", "google": "#2ed573"}
    _sb_role_labels = {"admin": "👑 ADMIN", "google": "🌐 GOOGLE"}
    _sb_rc  = _sb_role_colors.get(st.session_state.user_role, "#4f7bff")
    _sb_rl  = _sb_role_labels.get(st.session_state.user_role, st.session_state.user_role.upper())
    _sb_nom = st.session_state.user_nom or "Utilisateur"
    _sb_em  = st.session_state.user_email
    if st.session_state.user_picture:
        _sb_pic = f'<img src="{st.session_state.user_picture}" style="width:40px;height:40px;border-radius:50%;border:2.5px solid {_sb_rc};object-fit:cover;margin-right:0.7rem;flex-shrink:0;" />'
    else:
        _sb_ini = (_sb_nom or _sb_em or "?")[0].upper()
        _sb_pic = f'<div style="width:40px;height:40px;border-radius:50%;background:linear-gradient(135deg,#4f7bff,#00d4ff);border:2.5px solid {_sb_rc};display:inline-flex;align-items:center;justify-content:center;font-weight:900;font-size:17px;color:#fff;margin-right:0.7rem;flex-shrink:0;">{_sb_ini}</div>'

    components.html(f"""
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@600;700;800;900&display=swap" rel="stylesheet">
    <div style="font-family:'Poppins',sans-serif;background:linear-gradient(135deg,#0d1530,#111b3d);
        border:2px solid #2a3f5f;border-left:4px solid {_sb_rc};border-radius:12px;
        padding:0.9rem 1rem;margin-bottom:0.7rem;">
        <div style="display:flex;align-items:center;margin-bottom:0.5rem;">
            {_sb_pic}
            <div style="flex:1;min-width:0;">
                <div style="font-size:13px;font-weight:900;color:#ffffff;white-space:nowrap;
                    overflow:hidden;text-overflow:ellipsis;">{_sb_nom}</div>
                <div style="font-size:10.5px;color:#8fa8cc;white-space:nowrap;overflow:hidden;
                    text-overflow:ellipsis;">{_sb_em}</div>
            </div>
        </div>
        <span style="display:inline-block;padding:0.2rem 0.65rem;border-radius:20px;font-size:10px;
            font-weight:900;color:{_sb_rc};border:1.5px solid {_sb_rc};
            background:rgba(0,0,0,0.25);text-transform:uppercase;">{_sb_rl}</span>
    </div>
    """, height=105)

    # ── Bouton déconnexion avec avis ──────────────────────────────────────────
    if "show_feedback_form" not in st.session_state:
        st.session_state["show_feedback_form"] = False

    if not st.session_state["show_feedback_form"]:
        if st.button("🔐 SE DÉCONNECTER", use_container_width=True):
            st.session_state["show_feedback_form"] = True
            st.rerun()
    else:
        components.html("""
        <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@600;700;800;900&display=swap" rel="stylesheet">
        <div style="font-family:'Poppins',sans-serif;background:linear-gradient(135deg,#0d1530,#111b3d);
            border:2px solid #4f7bff;border-radius:14px;padding:1rem;margin-bottom:0.5rem;">
            <div style="font-size:14px;font-weight:900;color:#ffffff;margin-bottom:0.2rem;">
                💬 Votre avis compte !
            </div>
            <div style="font-size:11px;color:#a0c0ff;margin-bottom:0.8rem;font-weight:600;">
                Avant de partir, partagez votre expérience avec TrustLink.
            </div>
            <form action="https://formspree.io/f/xzdkyrza" method="POST"
                style="display:flex;flex-direction:column;gap:0.5rem;">
                <select name="note" required
                    style="background:#0d1530;color:#e0e8ff;border:1.5px solid #3a5a9f;
                        border-radius:8px;padding:0.4rem 0.6rem;font-size:12px;font-weight:700;
                        font-family:'Poppins',sans-serif;outline:none;">
                    <option value="" disabled selected style="color:#5a7aaa;">⭐ Note globale</option>
                    <option value="5 - Excellent">⭐⭐⭐⭐⭐ Excellent</option>
                    <option value="4 - Très bien">⭐⭐⭐⭐ Très bien</option>
                    <option value="3 - Bien">⭐⭐⭐ Bien</option>
                    <option value="2 - Moyen">⭐⭐ Moyen</option>
                    <option value="1 - À améliorer">⭐ À améliorer</option>
                </select>
                <textarea name="message" rows="3" placeholder="Un commentaire ? Une suggestion ?"
                    style="background:#0d1530;color:#e0e8ff;border:1.5px solid #3a5a9f;
                        border-radius:8px;padding:0.4rem 0.6rem;font-size:11.5px;
                        font-family:'Poppins',sans-serif;resize:none;outline:none;"></textarea>
                <input type="hidden" name="_subject" value="Avis TrustLink v5.0" />
                <button type="submit"
                    style="background:linear-gradient(135deg,#4f7bff,#00d4ff);color:#fff;
                        border:none;border-radius:8px;padding:0.45rem;font-size:12px;
                        font-weight:900;cursor:pointer;font-family:'Poppins',sans-serif;
                        text-transform:uppercase;letter-spacing:1px;">
                    📨 ENVOYER &amp; DÉCONNECTER
                </button>
            </form>
        </div>
        """, height=260)

        col_skip, col_cancel = st.columns(2)
        with col_skip:
            if st.button("⏭️ Ignorer", use_container_width=True):
                for _sk in list(st.session_state.keys()):
                    del st.session_state[_sk]
                st.rerun()
        with col_cancel:
            if st.button("↩️ Annuler", use_container_width=True):
                st.session_state["show_feedback_form"] = False
                st.rerun()

    components.html("""
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@600;700;800;900&display=swap" rel="stylesheet">
    <div style="font-family:'Poppins',sans-serif;position:relative;overflow:hidden;
        background:radial-gradient(ellipse at 50% 0%, #0d1f6e 0%, #050d3a 60%, #020818 100%);
        border:1.5px solid #1e3070;border-radius:14px;padding:1.2rem 1rem;margin-top:0.8rem;">

      <!-- Étoiles mini -->
      <canvas id="sbc" style="position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none;opacity:0.7;"></canvas>

      <!-- Réseau léger -->
      <svg style="position:absolute;top:0;left:0;width:100%;height:100%;opacity:0.12;pointer-events:none;" xmlns="http://www.w3.org/2000/svg">
        <line x1="0%"  y1="20%" x2="50%"  y2="50%"  stroke="#4f7bff" stroke-width="0.6"/>
        <line x1="50%" y1="50%" x2="100%" y2="15%"  stroke="#4f7bff" stroke-width="0.6"/>
        <line x1="10%" y1="80%" x2="60%"  y2="50%"  stroke="#4f7bff" stroke-width="0.6"/>
        <line x1="60%" y1="50%" x2="100%" y2="80%"  stroke="#4f7bff" stroke-width="0.6"/>
        <circle cx="50%"  cy="50%"  r="2" fill="#4f7bff" opacity="0.8"/>
        <circle cx="0%"   cy="20%"  r="2" fill="#4f7bff" opacity="0.6"/>
        <circle cx="100%" cy="15%"  r="2" fill="#4f7bff" opacity="0.6"/>
        <circle cx="100%" cy="80%"  r="2" fill="#4f7bff" opacity="0.6"/>
      </svg>

      <!-- Contenu -->
      <div style="position:relative;z-index:2;">
        <!-- Auteur -->
        <div style="margin-bottom:0.75rem;">
          <div style="font-size:9px;color:#5a7adf;text-transform:uppercase;
              letter-spacing:1.8px;font-weight:800;margin-bottom:0.25rem;">👨‍💻 Auteur</div>
          <div style="font-size:12.5px;color:#ffffff;font-weight:900;
              text-shadow:0 0 12px rgba(79,123,255,0.4);">Anoh Amon Francklin Hemerson</div>
        </div>

        <!-- Séparateur -->
        <div style="height:1px;background:linear-gradient(90deg,#4f7bff44,transparent);margin:0.5rem 0;"></div>

        <!-- Superviseur -->
        <div style="margin-bottom:0.75rem;">
          <div style="font-size:9px;color:#5a7adf;text-transform:uppercase;
              letter-spacing:1.8px;font-weight:800;margin-bottom:0.25rem;">👨‍💼 Superviseur</div>
          <div style="font-size:12px;color:#4f7bff;font-weight:800;">M. AKPOSSO DIDIER MARTIAL</div>
        </div>

        <!-- Séparateur -->
        <div style="height:1px;background:linear-gradient(90deg,#4f7bff44,transparent);margin:0.5rem 0;"></div>

        <!-- Badges version -->
        <div style="display:flex;gap:0.4rem;flex-wrap:wrap;align-items:center;justify-content:center;margin-top:0.4rem;">
          <span style="background:rgba(79,123,255,0.15);border:1px solid rgba(79,123,255,0.4);
              color:#a0bfff;padding:0.15rem 0.6rem;border-radius:20px;font-size:9.5px;font-weight:800;">
            © 2026
          </span>
          <span style="background:rgba(255,71,87,0.12);border:1px solid rgba(255,71,87,0.35);
              color:#ff8fa0;padding:0.15rem 0.6rem;border-radius:20px;font-size:9.5px;font-weight:800;">
            v5.0 Premium
          </span>
          <span style="background:rgba(46,213,115,0.12);border:1px solid rgba(46,213,115,0.35);
              color:#2ed573;padding:0.15rem 0.6rem;border-radius:20px;font-size:9.5px;font-weight:800;">
            Build 2026-04
          </span>
        </div>
      </div>
    </div>
    <script>
      const sbc=document.getElementById('sbc');
      const sbx=sbc.getContext('2d');
      function rss(){
        sbc.width=sbc.offsetWidth;sbc.height=sbc.offsetHeight;
        sbx.clearRect(0,0,sbc.width,sbc.height);
        for(let i=0;i<60;i++){
          const px=Math.random()*sbc.width,py=Math.random()*sbc.height,pr=Math.random()*1+0.2;
          sbx.beginPath();sbx.arc(px,py,pr,0,Math.PI*2);
          sbx.fillStyle=`rgba(255,255,255,${Math.random()*0.6+0.1})`;sbx.fill();
        }
      }
      rss();
    </script>
    """, height=195)

# Horloge update
clock_placeholder.markdown(
    f'<div style="background:#111b3d; border:2px solid #2a3f5f; border-radius:10px; padding:1rem; text-align:center; font-family:\'JetBrains Mono\', monospace; font-size:22px; font-weight:700; color:#4f7bff; letter-spacing:3px;">{datetime.now().strftime("%H:%M:%S")}</div>',
    unsafe_allow_html=True
)

# ═════════════════════════════════════════════════════════════════════════════════
# 🎯 HEADER PRINCIPAL
# ═════════════════════════════════════════════════════════════════════════════════
components.html("""
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;600;700;800;900&display=swap" rel="stylesheet">
<style>
  @keyframes pulse-glow2 {
    0%,100% { filter: drop-shadow(0 0 14px rgba(79,123,255,0.7)); }
    50%      { filter: drop-shadow(0 0 32px rgba(79,123,255,1)); }
  }
  @keyframes float2 {
    0%,100% { transform: translateY(0px); }
    50%      { transform: translateY(-6px); }
  }
  @keyframes shimmer2 { 0%,100%{opacity:0.4;} 50%{opacity:1;} }
  @keyframes fadeUp2 { from{opacity:0;transform:translateY(20px);} to{opacity:1;transform:translateY(0);} }
</style>
<div id="hero2" style="position:relative;width:100%;
    background:radial-gradient(ellipse at 50% 30%, #0d2280 0%, #050d3a 45%, #020818 100%);
    border-radius:20px;overflow:hidden;display:flex;flex-direction:column;
    align-items:center;justify-content:center;padding:2.2rem 2rem 1.8rem;
    box-shadow:0 24px 70px rgba(0,0,50,0.8);border:1.5px solid #1e3070;">

  <!-- Canvas étoiles -->
  <canvas id="stars2" style="position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none;"></canvas>

  <!-- Réseau SVG -->
  <svg style="position:absolute;top:0;left:0;width:100%;height:100%;opacity:0.28;pointer-events:none;" xmlns="http://www.w3.org/2000/svg">
    <line x1="5%"  y1="15%" x2="30%" y2="45%" stroke="#00d4ff" stroke-width="0.9"/>
    <line x1="30%" y1="45%" x2="65%" y2="10%" stroke="#00d4ff" stroke-width="0.7"/>
    <line x1="65%" y1="10%" x2="95%" y2="55%" stroke="#4f7bff" stroke-width="0.7"/>
    <line x1="8%"  y1="75%" x2="40%" y2="45%" stroke="#4f7bff" stroke-width="0.7"/>
    <line x1="40%" y1="45%" x2="70%" y2="85%" stroke="#4f7bff" stroke-width="0.7"/>
    <line x1="70%" y1="85%" x2="95%" y2="55%" stroke="#4f7bff" stroke-width="0.7"/>
    <circle cx="5%"  cy="15%" r="3" fill="#00d4ff" opacity="0.9"/>
    <circle cx="30%" cy="45%" r="3" fill="#00d4ff" opacity="0.9"/>
    <circle cx="65%" cy="10%" r="3" fill="#00d4ff" opacity="0.9"/>
    <circle cx="95%" cy="55%" r="3" fill="#00d4ff" opacity="0.9"/>
    <circle cx="8%"  cy="75%" r="3" fill="#00d4ff" opacity="0.9"/>
    <circle cx="70%" cy="85%" r="3" fill="#00d4ff" opacity="0.9"/>
  </svg>

  <!-- Bouclier SVG animé -->
  <div style="animation:float2 3.5s ease-in-out infinite;margin-bottom:1rem;position:relative;z-index:2;">
    <svg width="68" height="82" viewBox="0 0 80 96" xmlns="http://www.w3.org/2000/svg"
         style="animation:pulse-glow2 2.5s ease-in-out infinite;">
      <defs>
        <linearGradient id="sL2" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#1a3a9f"/><stop offset="100%" stop-color="#0d1f6e"/>
        </linearGradient>
        <linearGradient id="sR2" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#cc1a1a"/><stop offset="100%" stop-color="#8b0000"/>
        </linearGradient>
      </defs>
      <path d="M40 4 L76 18 L76 48 C76 68 60 84 40 92 C20 84 4 68 4 48 L4 18 Z"
            fill="none" stroke="#4f7bff" stroke-width="3" opacity="0.9"/>
      <path d="M40 4 L4 18 L4 48 C4 68 20 84 40 92 Z" fill="url(#sL2)"/>
      <path d="M40 4 L76 18 L76 48 C76 68 60 84 40 92 Z" fill="url(#sR2)"/>
      <line x1="40" y1="4" x2="40" y2="92" stroke="#fff" stroke-width="1.5" opacity="0.6"/>
      <text x="40" y="58" text-anchor="middle" font-family="Poppins,sans-serif"
            font-size="26" font-weight="900" fill="white" opacity="0.95">H</text>
    </svg>
  </div>

  <!-- Titre -->
  <h1 style="font-family:'Poppins',sans-serif;font-size:clamp(20px,3.5vw,34px);
      font-weight:900;color:#ffffff;margin:0;text-transform:uppercase;
      letter-spacing:3px;text-align:center;position:relative;z-index:2;
      text-shadow:0 0 28px rgba(79,123,255,0.6);animation:fadeUp2 0.7s ease both;">
    HEMERSON TRUSTLINK
  </h1>

  <!-- Sous-titre cyan comme sur la photo -->
  <p style="font-family:'Poppins',sans-serif;font-size:clamp(13px,1.9vw,17px);
      color:#00e5ff;font-weight:700;margin:0.5rem 0 0;text-align:center;
      position:relative;z-index:2;animation:fadeUp2 0.85s ease both;
      text-shadow:0 0 18px rgba(0,229,255,0.55);">
    ● Détection Intelligente de Fraude Financière
  </p>

  <!-- Séparateur -->
  <div style="width:50px;height:2px;background:linear-gradient(90deg,#00e5ff,#4f7bff);
      margin:0.8rem auto;border-radius:2px;position:relative;z-index:2;"></div>

  <!-- Badges texte inline comme sur la photo -->
  <p style="font-family:'Poppins',sans-serif;font-size:clamp(10px,1.3vw,12.5px);
      color:#8ab4d8;font-weight:500;margin:0;text-align:center;
      position:relative;z-index:2;animation:fadeUp2 1s ease both;letter-spacing:0.3px;">
    Machine Learning Avancée &nbsp;•&nbsp; Analyse Temps Réel - 30 Caractéristiques
    &nbsp;•&nbsp; Score IA Certifié &nbsp;•&nbsp;
    <span style="color:#00e5ff;font-weight:700;">V5.0</span>
  </p>
</div>
<script>
  const c2 = document.getElementById('stars2');
  const x2 = c2.getContext('2d');
  function rs2() {
    c2.width=c2.offsetWidth; c2.height=c2.offsetHeight;
    x2.clearRect(0,0,c2.width,c2.height);
    for(let i=0;i<120;i++){
      const px=Math.random()*c2.width, py=Math.random()*c2.height, pr=Math.random()*1.6+0.2;
      x2.beginPath(); x2.arc(px,py,pr,0,Math.PI*2);
      const isCyan = Math.random() > 0.7;
      x2.fillStyle = isCyan
        ? `rgba(0,212,255,${Math.random()*0.8+0.2})`
        : `rgba(255,255,255,${Math.random()*0.65+0.2})`;
      x2.fill();
    }
  }
  rs2();
</script>
""", height=310)

# ═════════════════════════════════════════════════════════════════════════════════
# 📑 ONGLETS PRINCIPAUX
# ═════════════════════════════════════════════════════════════════════════════════
# ═════════════════════════════════════════════════════════════════════════════════
# 🔐 SYSTÈME LOG VISITEURS — Admin seulement
# ═════════════════════════════════════════════════════════════════════════════════
import json as _json_visitors

_VISITORS_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "trustlink_visitors.json"
)

def _visitors_load() -> list:
    """Charge la liste des visiteurs depuis le fichier JSON."""
    try:
        if os.path.exists(_VISITORS_PATH) and os.path.getsize(_VISITORS_PATH) > 0:
            with open(_VISITORS_PATH, "r", encoding="utf-8") as f:
                return _json_visitors.load(f)
    except Exception:
        pass
    return []

def _visitors_save(data: list):
    """Sauvegarde la liste des visiteurs."""
    try:
        with open(_VISITORS_PATH, "w", encoding="utf-8") as f:
            _json_visitors.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[Visitors] Erreur écriture : {e}")

def _visitors_log(email: str, nom: str, role: str, login_type: str):
    """Enregistre ou met à jour la dernière connexion d'un utilisateur."""
    visitors = _visitors_load()
    now_str = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    # Chercher si déjà existant
    for v in visitors:
        if v.get("email") == email:
            v["derniere_connexion"] = now_str
            v["nb_connexions"]      = v.get("nb_connexions", 1) + 1
            v["nom"]                = nom
            v["role"]               = role
            v["login_type"]         = login_type
            _visitors_save(visitors)
            return
    # Nouvel utilisateur
    visitors.append({
        "email":               email,
        "nom":                 nom,
        "role":                role,
        "login_type":          login_type,
        "premiere_connexion":  now_str,
        "derniere_connexion":  now_str,
        "nb_connexions":       1,
    })
    _visitors_save(visitors)

# Logger la connexion courante (une seule fois par session)
_cur_email_log = st.session_state.get("user_email", "")
_cur_nom_log   = st.session_state.get("user_nom", "")
_cur_role_log  = st.session_state.get("user_role", "")
_cur_type_log  = st.session_state.get("login_type", "")
if _cur_email_log and not st.session_state.get("_visitor_logged"):
    _visitors_log(_cur_email_log, _cur_nom_log, _cur_role_log, _cur_type_log)
    st.session_state["_visitor_logged"] = True

_is_admin_panel = (st.session_state.get("user_role", "") == "admin"
                   or st.session_state.get("user_email", "") == _ADMIN_EMAIL)

# ─────────────────────────────────────────────────────────────────────────────

_tabs_list = ["🔍 ANALYSER TRANSACTION", "📋 HISTORIQUE", "📊 TABLEAU DE BORD", "📁 ANALYSE EN LOT", "📖 GUIDE"]
if _is_admin_panel:
    _tabs_list.append("🔐 ADMIN")

_tabs_result = st.tabs(_tabs_list)
tab1 = _tabs_result[0]
tab2 = _tabs_result[1]
tab3 = _tabs_result[2]
tab4 = _tabs_result[3]
tab_guide = _tabs_result[4]
tab5 = _tabs_result[5] if _is_admin_panel else None

# ╔═════════════════════════════════════════════════════════════════════════════╗
# ║ ONGLET 1 - ANALYSE TRANSACTION                                              ║
# ╚═════════════════════════════════════════════════════════════════════════════╝
with tab1:
    st.markdown("""
    <div class="card-premium animate-in">
        <div class="card-title">💳 DONNÉES DE LA TRANSACTION</div>
        <div class="card-subtitle">Renseignez les paramètres pour analyse instantanée</div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        montant = st.number_input("💸 MONTANT (FCFA)", min_value=0.0, format="%.2f", value=5000.0)
    with col2:
        horodatage = st.number_input("⏱️ HORODATAGE (secondes)", min_value=0.0, value=43200.0)
    with col3:
        libelle = st.text_input("📝 DESCRIPTION TRANSACTION", placeholder="Ex: Achat en ligne")

    st.markdown("""
    <div class="card-premium animate-in">
        <div class="card-title">🧬 VECTEURS D'ANALYSE (V1–V28)</div>
        <div class="card-subtitle">Composantes PCA • Survolez le nom pour voir la description de chaque variable</div>
    </div>
    """, unsafe_allow_html=True)

    vecteurs = []
    _, *inner_cols, _ = st.columns([0.5] + [1]*7 + [0.5])
    for i in range(1, 29):
        with inner_cols[(i - 1) % 7]:
            tooltip = TOOLTIPS_V.get(i, "")
            st.markdown(f'<div class="tooltip-container"><span style="font-size:11px; color:#a0aec0; font-weight:700; text-transform:uppercase; letter-spacing:0.5px;">V{i} ℹ️<span class="tooltip-text">{tooltip}</span></span></div>', unsafe_allow_html=True)
            v = st.number_input(f"V{i}", value=0.0, key=f"v{i}", label_visibility="collapsed")
            vecteurs.append(v)

    st.markdown("")
    # Notes analyste
    notes_analyste = st.text_area("💬 NOTES DE L'ANALYSTE (optionnel)", placeholder="Ex: Client vérifié, en attente confirmation banque...", height=80)

    col_btn, col_info = st.columns([1, 3])
    with col_btn:
        analyser = st.button("🔍 ANALYSER", use_container_width=True, type="primary")
    with col_info:
        st.caption("✅ ANALYSÉ SÉCURISÉ | ⚡ INSTANTANÉ | 💾 SAUVEGARDÉ | 🆓 100% GRATUIT")

    if analyser and modele is not None:
        with st.spinner("🔄 ANALYSE EN COURS..."):
            time.sleep(0.4)

            entree = np.array([horodatage] + vecteurs + [montant]).reshape(1, -1)
            entree_scaled = scaler.transform(entree)
            proba = modele.predict_proba(entree_scaled)[0][1]
            score = proba * 100
            pred = modele.predict(entree_scaled)[0]
            ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            lbl = libelle.strip() if libelle.strip() else f"TRANSACTION #{len(st.session_state.historique)+1}"

            if score > seuil_fraude:
                verdict = "FRAUDE"
                couleur = "danger"
                icone = "🚨"
                conseil = "⛔ TRANSACTION À BLOQUER IMMÉDIATEMENT"
                badge_class = "danger"
            elif score > seuil_suspect:
                verdict = "SUSPECT"
                couleur = "warning"
                icone = "⚠️"
                conseil = "🔍 VÉRIFICATION MANUELLE RECOMMANDÉE"
                badge_class = "warning"
            else:
                verdict = "SAINE"
                couleur = "success"
                icone = "✅"
                conseil = "✔️ TRANSACTION APPROUVÉE - PROFIL NORMAL"
                badge_class = "success"

            # ── Alerte sonore si FRAUDE ────────────────────────────────────
            if verdict == "FRAUDE":
                components.html("""
                <script>
                try {
                    var ctx = new (window.AudioContext || window.webkitAudioContext)();
                    function beep(freq, duration, vol) {
                        var osc = ctx.createOscillator();
                        var gain = ctx.createGain();
                        osc.connect(gain); gain.connect(ctx.destination);
                        osc.frequency.value = freq; osc.type = 'square';
                        gain.gain.value = vol;
                        osc.start(); osc.stop(ctx.currentTime + duration);
                    }
                    beep(880, 0.15, 0.3);
                    setTimeout(function(){ beep(660, 0.15, 0.3); }, 200);
                    setTimeout(function(){ beep(880, 0.3, 0.4); }, 400);
                } catch(e) { console.log('Audio non disponible'); }
                </script>
                """, height=0)

            st.session_state.historique.append({
                "id": len(st.session_state.historique) + 1,
                "date": ts,
                "libelle": lbl,
                "montant": montant,
                "verdict": verdict,
                "score": round(score, 2),
                "prediction": int(pred),
                "notes": notes_analyste.strip() if notes_analyste else "",
                "vecteurs": vecteurs[:],
                "horodatage": horodatage,
            })

            st.success(f"✅ ANALYSE #{len(st.session_state.historique)} COMPLÉTÉE AVEC SUCCÈS")

            # Confettis si 0 fraude sur 10+ transactions
            total_sess = len(st.session_state.historique)
            fraudes_sess = sum(1 for h in st.session_state.historique if h["verdict"] == "FRAUDE")
            if total_sess >= 10 and fraudes_sess == 0:
                st.balloons()
                st.success("🎉 FÉLICITATIONS ! 10+ transactions analysées sans aucune fraude détectée !")

            st.markdown("<br>", unsafe_allow_html=True)

            col_res, col_det = st.columns([1.2, 1])

            if couleur == 'success':
                progress_class = 'success'
            elif couleur == 'danger':
                progress_class = 'danger'
            else:
                progress_class = 'warning'

            with col_res:
                st.markdown(f"""
                <div class="verdict-box-premium verdict-{couleur} animate-in">
                    <div style="margin-bottom:2rem;">
                        <span class="badge-premium badge-{badge_class}">{icone} {verdict}</span>
                    </div>
                    <div style="font-size:56px; font-weight:900; color:var(--text-primary); margin-bottom:2rem; line-height:1;">{score:.1f}%</div>
                    <div style="font-size:17px; color:var(--text-secondary); margin-bottom:2.5rem; font-weight:800; text-transform:uppercase; letter-spacing:0.5px;">{conseil}</div>
                    <div class="progress-bar-premium">
                        <div class="progress-fill progress-{progress_class}" style="width:{min(score,100)}%;"></div>
                    </div>
                    <div style="margin-top:1.5rem; display:flex; justify-content:space-between; font-size:12px; color:var(--text-muted); font-weight:800; text-transform:uppercase;">
                        <span>🟢 SAINE (0%)</span><span>🟡 SUSPECT ({seuil_suspect}%)</span><span>🔴 FRAUDE ({seuil_fraude}%)</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)

            with col_det:
                pred_label = "FRAUDE" if pred == 1 else "LÉGITIME"
                confiance = abs(score - 50) * 2
                ana_id = len(st.session_state.historique)
                notes_det_html = f'<div style="margin-top:0.5rem;padding:0.6rem 0.8rem;background:rgba(255,165,2,0.1);border-left:3px solid #ffa502;border-radius:6px;font-size:13px;color:#ffa502;">📝 {notes_analyste}</div>' if notes_analyste else ""
                components.html(f"""
                <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@600;700;800;900&display=swap" rel="stylesheet">
                <div style="font-family:'Poppins',sans-serif;background:linear-gradient(135deg,#111b3d,#192551);
                    border:3px solid #2a3f5f;border-radius:16px;padding:2rem;height:100%;
                    box-shadow:0 10px 32px rgba(0,0,0,0.4);">
                    <div style="font-size:18px;font-weight:900;color:#ffffff;margin-bottom:1.2rem;
                        text-transform:uppercase;letter-spacing:1px;border-bottom:2px solid #2a3f5f;padding-bottom:0.8rem;">
                        📊 DÉTAILS COMPLETS
                    </div>
                    <div style="font-size:14px;line-height:2.4;color:#e0e7ff;">
                        <div style="display:flex;justify-content:space-between;border-bottom:1px solid rgba(58,79,111,0.4);padding:0.2rem 0;">
                            <span style="color:#a0aec0;font-weight:700;">MONTANT</span>
                            <span style="color:#ffffff;font-weight:900;">{montant:,.0f} FCFA</span>
                        </div>
                        <div style="display:flex;justify-content:space-between;border-bottom:1px solid rgba(58,79,111,0.4);padding:0.2rem 0;">
                            <span style="color:#a0aec0;font-weight:700;">PRÉDICTION ML</span>
                            <span style="color:#{'ff4757' if pred == 1 else '2ed573'};font-weight:900;">{pred_label}</span>
                        </div>
                        <div style="display:flex;justify-content:space-between;border-bottom:1px solid rgba(58,79,111,0.4);padding:0.2rem 0;">
                            <span style="color:#a0aec0;font-weight:700;">CONFIANCE</span>
                            <span style="color:#4f7bff;font-weight:900;">{confiance:.0f}%</span>
                        </div>
                        <div style="display:flex;justify-content:space-between;border-bottom:1px solid rgba(58,79,111,0.4);padding:0.2rem 0;">
                            <span style="color:#a0aec0;font-weight:700;">DATE/HEURE</span>
                            <span style="color:#ffffff;font-weight:700;font-size:12px;">{ts}</span>
                        </div>
                        <div style="display:flex;justify-content:space-between;border-bottom:1px solid rgba(58,79,111,0.4);padding:0.2rem 0;">
                            <span style="color:#a0aec0;font-weight:700;">DESCRIPTION</span>
                            <span style="color:#ffffff;font-weight:700;">{lbl}</span>
                        </div>
                        <div style="display:flex;justify-content:space-between;padding:0.2rem 0;">
                            <span style="color:#a0aec0;font-weight:700;">ID ANALYSE</span>
                            <span style="color:#ffffff;font-weight:900;">#{ana_id}</span>
                        </div>
                    </div>
                    {notes_det_html}
                </div>
                """, height=360)

            # ── EXPLICATION IA (perturbation) ───────────────────────────────
            st.markdown("### 🧮 EXPLICATION IA — TOP 5 VARIABLES INFLUENTES")
            if modele is not None and scaler is not None:
                influences = []
                base_score = score
                for i, val in enumerate(vecteurs):
                    perturbed = vecteurs[:]
                    perturbed[i] = val + 1.0
                    e2 = np.array([horodatage] + perturbed + [montant]).reshape(1, -1)
                    e2s = scaler.transform(e2)
                    ps = modele.predict_proba(e2s)[0][1] * 100
                    influences.append((f"V{i+1}", abs(ps - base_score), ps - base_score))
                # Montant
                e_m = np.array([horodatage] + vecteurs + [montant * 1.1]).reshape(1, -1)
                e_ms = scaler.transform(e_m)
                ps_m = modele.predict_proba(e_ms)[0][1] * 100
                influences.append(("Montant", abs(ps_m - base_score), ps_m - base_score))
                # Horodatage
                e_h = np.array([horodatage + 3600] + vecteurs + [montant]).reshape(1, -1)
                e_hs = scaler.transform(e_h)
                ps_h = modele.predict_proba(e_hs)[0][1] * 100
                influences.append(("Horodatage", abs(ps_h - base_score), ps_h - base_score))

                influences.sort(key=lambda x: x[1], reverse=True)
                top5 = influences[:5]

                cols_shap = st.columns(5)
                for idx, (var, impact, delta) in enumerate(top5):
                    direction = "🔴 +" if delta > 0 else "🟢 -"
                    with cols_shap[idx]:
                        st.markdown(f"""
                        <div class="stat-box" style="padding:1.2rem;">
                            <div style="font-size:16px; font-weight:900; color:#4f7bff; margin-bottom:0.5rem;">{var}</div>
                            <div style="font-size:11px; color:#a0aec0; margin-bottom:0.5rem; text-transform:uppercase;">Impact</div>
                            <div style="font-size:18px; font-weight:900; color:{'#ff4757' if delta > 0 else '#2ed573'};">{direction}{impact:.2f}%</div>
                        </div>
                        """, unsafe_allow_html=True)

# ╔═════════════════════════════════════════════════════════════════════════════╗
# ║ ONGLET 2 - HISTORIQUE                                                       ║
# ╚═════════════════════════════════════════════════════════════════════════════╝
with tab2:
    if not st.session_state.historique:
        components.html("""
        <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@600;700;800;900&display=swap" rel="stylesheet">
        <div style="text-align:center; padding:3.2rem 2rem; background:linear-gradient(135deg,#111b3d,#0d1530);
            border:2px dashed #3a4f6f; border-radius:16px; box-shadow:0 8px 28px rgba(0,0,0,0.3); font-family:'Poppins',sans-serif;">
            <div style="font-size:52px; margin-bottom:1rem;">📋</div>
            <h3 style="color:#ffffff; margin:0 0 0.8rem; font-size:22px; font-weight:900; text-transform:uppercase;">AUCUNE ANALYSE EFFECTUÉE</h3>
            <p style="color:#a0aec0; margin:0 auto; font-size:14px; font-weight:600; line-height:1.7; max-width:420px;">
                Lancez votre première analyse dans l'onglet <strong style="color:#4f7bff;">ANALYSER TRANSACTION</strong>
            </p>
        </div>
        """, height=260)
    else:
        col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
        with col1:
            st.markdown("### 📊 HISTORIQUE COMPLET DES ANALYSES")
        with col2:
            if st.button("📥 EXPORTER CSV", use_container_width=True):
                df_exp = pd.DataFrame([{k: v for k, v in h.items() if k not in ["vecteurs"]} for h in st.session_state.historique])
                csv = df_exp.to_csv(index=False).encode('utf-8')
                st.download_button("⬇️ TÉLÉCHARGER CSV", csv, "trustlink_export.csv", "text/csv", use_container_width=True)
        with col3:
            if st.button("📄 EXPORT PDF", use_container_width=True):
                # PDF simple via HTML print
                rows_html = ""
                for h in st.session_state.historique:
                    color = "#ff4757" if h["verdict"] == "FRAUDE" else "#ffa502" if h["verdict"] == "SUSPECT" else "#2ed573"
                    rows_html += f"""<tr>
                        <td style="padding:8px; border:1px solid #2a3f5f; color:#fff;">#{h['id']}</td>
                        <td style="padding:8px; border:1px solid #2a3f5f; color:#a0aec0;">{h['date']}</td>
                        <td style="padding:8px; border:1px solid #2a3f5f; color:#e0e7ff;">{h['libelle']}</td>
                        <td style="padding:8px; border:1px solid #2a3f5f; color:#fff; text-align:right;">{h['montant']:,.0f} FCFA</td>
                        <td style="padding:8px; border:1px solid #2a3f5f; color:{color}; font-weight:900;">{h['verdict']}</td>
                        <td style="padding:8px; border:1px solid #2a3f5f; color:#4f7bff;">{h['score']:.1f}%</td>
                        <td style="padding:8px; border:1px solid #2a3f5f; color:#a0aec0; font-size:11px;">{h.get('notes','')}</td>
                    </tr>"""
                total_h = len(st.session_state.historique)
                fraudes_h = sum(1 for h in st.session_state.historique if h["verdict"] == "FRAUDE")
                pdf_html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
                <title>Rapport TrustLink</title>
                <style>body{{font-family:Arial,sans-serif;background:#0a0e27;color:#fff;padding:2rem;}}
                h1{{color:#4f7bff;}} table{{width:100%;border-collapse:collapse;}} th{{background:#111b3d;color:#a0aec0;padding:10px;border:1px solid #2a3f5f;text-transform:uppercase;font-size:12px;}}
                .header{{background:linear-gradient(135deg,#111b3d,#192551);padding:2rem;border-radius:12px;margin-bottom:2rem;border:2px solid #2a3f5f;}}
                .meta{{color:#a0aec0;font-size:13px;margin-top:0.5rem;}}
                </style></head><body>
                <div class="header">
                <h1>🛡️ HEMERSON TRUSTLINK v5.0</h1>
                <p class="meta">Rapport d'analyse — Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}</p>
                <p class="meta">Auteur: Anoh Amon Francklin Hemerson &nbsp;|&nbsp; Total: {total_h} transactions &nbsp;|&nbsp; Fraudes: {fraudes_h}</p>
                </div>
                <table><thead><tr><th>#</th><th>Date</th><th>Description</th><th>Montant</th><th>Verdict</th><th>Score</th><th>Notes</th></tr></thead>
                <tbody>{rows_html}</tbody></table>
                <script>window.print(); window.close();</script>
                </body></html>"""
                b64 = base64.b64encode(pdf_html.encode()).decode()
                st.markdown(f'<a href="data:text/html;base64,{b64}" target="_blank" download="rapport_trustlink.html" style="display:inline-block;background:linear-gradient(135deg,#4f7bff,#00d4ff);color:#fff;padding:0.6rem 1.2rem;border-radius:8px;font-weight:900;text-decoration:none;font-size:13px;margin-top:0.5rem;">📄 TÉLÉCHARGER RAPPORT</a>', unsafe_allow_html=True)

        with col4:
            if st.button("🗑️ RÉINITIALISER", use_container_width=True):
                st.session_state.historique = []
                st.session_state.critiques = set()
                st.rerun()

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

        # Afficher critiques d'abord
        hist_sorted = sorted(st.session_state.historique, key=lambda x: (x["id"] not in st.session_state.critiques, -x["id"]))

        for item in hist_sorted:
            verdict = item["verdict"]
            score = item["score"]
            is_critique = item["id"] in st.session_state.critiques

            if verdict == "FRAUDE":
                badge_color = "#ff4757"; badge_bg = "rgba(255,71,87,0.12)"; bar_grad = "linear-gradient(90deg,#ff4757,#ff6b7a)"
            elif verdict == "SUSPECT":
                badge_color = "#ffa502"; badge_bg = "rgba(255,165,2,0.12)"; bar_grad = "linear-gradient(90deg,#ffa502,#ffb74d)"
            else:
                badge_color = "#2ed573"; badge_bg = "rgba(46,213,115,0.12)"; bar_grad = "linear-gradient(135deg,#4f7bff,#00d4ff)"

            border_color = "#ff0080" if is_critique else "#2a3f5f"
            critique_html = '<span style="display:inline-block;padding:0.2rem 0.6rem;border-radius:20px;font-size:10px;font-weight:900;background:rgba(255,0,128,0.15);color:#ff0080;border:2px solid #ff0080;margin-left:0.5rem;vertical-align:middle;">⭐ CRITIQUE</span>' if is_critique else ""
            notes_html = f'<div style="font-size:12px;color:#ffa502;margin-top:0.4rem;font-style:italic;">📝 {item.get("notes","")}</div>' if item.get("notes") else ""
            bar_pct = min(score, 100)
            card_height = 165 if item.get("notes") else 148

            col_card, col_pin = st.columns([9, 1])
            with col_card:
                components.html(f"""
                <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@600;700;800;900&display=swap" rel="stylesheet">
                <div style="font-family:'Poppins',sans-serif;background:linear-gradient(135deg,#111b3d,#192551);
                    border:3px solid {border_color};border-radius:14px;padding:1.4rem 1.6rem;
                    margin-bottom:0.2rem;box-shadow:0 6px 20px rgba(0,0,0,0.4);">
                    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem;">
                        <div style="flex:1;min-width:180px;">
                            <div style="font-weight:900;color:#ffffff;margin-bottom:0.3rem;font-size:15px;text-transform:uppercase;">
                                #{item['id']} — {item['libelle']} {critique_html}
                            </div>
                            <div style="font-size:12px;color:#a0aec0;font-weight:700;">{item['date']}</div>
                            {notes_html}
                        </div>
                        <div style="text-align:right;">
                            <div style="font-size:11px;color:#a0aec0;text-transform:uppercase;font-weight:800;margin-bottom:0.2rem;">MONTANT</div>
                            <div style="font-weight:900;color:#ffffff;font-size:15px;">{item['montant']:,.0f} FCFA</div>
                        </div>
                        <div style="text-align:right;">
                            <div style="font-size:11px;color:#a0aec0;text-transform:uppercase;font-weight:800;margin-bottom:0.2rem;">SCORE</div>
                            <div style="font-weight:900;color:#ffffff;font-size:15px;">{score:.1f}%</div>
                        </div>
                        <div>
                            <span style="display:inline-block;padding:0.5rem 1rem;border-radius:30px;font-size:12px;
                                font-weight:900;text-transform:uppercase;letter-spacing:1px;
                                background:{badge_bg};color:{badge_color};border:2px solid {badge_color};">
                                {verdict}
                            </span>
                        </div>
                    </div>
                    <div style="width:100%;height:10px;background:#0d1530;border-radius:5px;overflow:hidden;
                        margin-top:1rem;border:1px solid #2a3f5f;">
                        <div style="width:{bar_pct}%;height:100%;background:{bar_grad};border-radius:4px;"></div>
                    </div>
                </div>
                """, height=card_height)
            with col_pin:
                st.markdown("<div style='margin-top:0.3rem;'></div>", unsafe_allow_html=True)
                pin_label = "⭐ Retirer" if is_critique else "⭐ Marquer"
                if st.button(pin_label, key=f"pin_{item['id']}", use_container_width=True):
                    if item["id"] in st.session_state.critiques:
                        st.session_state.critiques.discard(item["id"])
                    else:
                        st.session_state.critiques.add(item["id"])
                    st.rerun()

# ╔═════════════════════════════════════════════════════════════════════════════╗
# ║ ONGLET 3 - TABLEAU DE BORD                                                  ║
# ╚═════════════════════════════════════════════════════════════════════════════╝
with tab3:
    if not st.session_state.historique:
        components.html("""
        <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@600;700;800;900&display=swap" rel="stylesheet">
        <div style="text-align:center;padding:3.2rem 2rem;background:linear-gradient(135deg,#111b3d,#0d1530);border:2px dashed #3a4f6f;border-radius:16px;box-shadow:0 8px 28px rgba(0,0,0,0.3);font-family:'Poppins',sans-serif;">
            <div style="font-size:52px;margin-bottom:1rem;">📊</div>
            <h3 style="color:#ffffff;margin:0 0 0.8rem;font-size:22px;font-weight:900;text-transform:uppercase;">AUCUNE DONNÉE DISPONIBLE</h3>
            <p style="color:#a0aec0;margin:0 auto;font-size:14px;font-weight:600;line-height:1.7;max-width:500px;">
                Effectuez des analyses pour voir les statistiques, graphiques et indicateurs
            </p>
        </div>
        """, height=260)
    else:
        df = pd.DataFrame(st.session_state.historique)
        total = len(df)
        fraudes = len(df[df.verdict == "FRAUDE"])
        suspects = len(df[df.verdict == "SUSPECT"])
        saines = len(df[df.verdict == "SAINE"])
        score_moy = df["score"].mean()
        montant_total = df["montant"].sum()
        taux_fraude = fraudes / total * 100

        # ── Score santé du portefeuille ────────────────────────────────────
        if taux_fraude < 5:
            grade = "A"; grade_desc = "EXCELLENT — Portefeuille très sain"; grade_col = "#2ed573"
        elif taux_fraude < 15:
            grade = "B"; grade_desc = "BON — Risque modéré acceptable"; grade_col = "#4f7bff"
        elif taux_fraude < 30:
            grade = "C"; grade_desc = "MOYEN — Surveillance renforcée requise"; grade_col = "#ffa502"
        else:
            grade = "D"; grade_desc = "CRITIQUE — Action immédiate nécessaire"; grade_col = "#ff4757"

        # Estimation pertes évitées
        montant_moyen = montant_total / total if total > 0 else 0
        pertes_evitees = fraudes * montant_moyen

        # ── RAPPORT EXÉCUTIF ───────────────────────────────────────────────
        st.markdown(f"""
        <div style="display:flex;align-items:center;gap:14px;
            background:linear-gradient(135deg,#111b3d,#0d1530);
            border:2px solid #4f7bff;border-left:5px solid #4f7bff;
            border-radius:12px;padding:1rem 1.5rem;margin:1.5rem 0 1rem 0;
            box-shadow:0 4px 18px rgba(79,123,255,0.18);">
            <span style="font-size:26px;">📋</span>
            <span style="font-size:15px;font-weight:900;color:#ffffff;
                font-family:'Poppins',sans-serif;text-transform:uppercase;
                letter-spacing:1.5px;">RAPPORT EXÉCUTIF — SESSION EN COURS</span>
            <div style="flex:1;height:1px;background:linear-gradient(90deg,#4f7bff55,transparent);margin-left:8px;"></div>
        </div>
        """, unsafe_allow_html=True)
        col_g1, col_g2, col_g3 = st.columns(3)

        with col_g1:
            st.markdown(f"""
            <div class="stat-box" style="padding:2rem; text-align:center;">
                <div class="stat-label">🏆 SCORE DE SANTÉ</div>
                <div style="font-size:4rem; font-weight:900; color:{grade_col}; line-height:1;">{grade}</div>
                <div style="font-size:12px; color:#a0aec0; margin-top:0.5rem; font-weight:700;">{grade_desc}</div>
            </div>
            """, unsafe_allow_html=True)

        with col_g2:
            st.markdown(f"""
            <div class="stat-box" style="padding:2rem; text-align:center;">
                <div class="stat-label">💰 PERTES ÉVITÉES EST.</div>
                <div style="font-size:1.8rem; font-weight:900; color:#2ed573; line-height:1.2;">{pertes_evitees:,.0f}</div>
                <div style="font-size:13px; color:#a0aec0; font-weight:700;">FCFA</div>
                <div style="font-size:11px; color:#5a6a85; margin-top:0.4rem;">{fraudes} fraude(s) × {montant_moyen:,.0f} FCFA moy.</div>
            </div>
            """, unsafe_allow_html=True)

        with col_g3:
            st.markdown(f"""
            <div class="stat-box" style="padding:2rem; text-align:center;">
                <div class="stat-label">📊 TAUX FRAUDE</div>
                <div style="font-size:3rem; font-weight:900; color:{'#ff4757' if taux_fraude>20 else '#ffa502' if taux_fraude>5 else '#2ed573'}; line-height:1;">{taux_fraude:.1f}%</div>
                <div style="font-size:12px; color:#a0aec0; margin-top:0.5rem; font-weight:700;">{fraudes}/{total} transactions</div>
            </div>
            """, unsafe_allow_html=True)

        # ── ALERTE DYNAMIQUE ───────────────────────────────────────────────
        if taux_fraude > 30:
            st.error(f"🚨 ALERTE CRITIQUE — Taux de fraude : **{taux_fraude:.1f}%** ({fraudes}/{total} transactions)")
        elif taux_fraude > 10:
            st.warning(f"⚠️ VIGILANCE — Taux de fraude modéré : **{taux_fraude:.1f}%** ({fraudes}/{total} transactions)")
        else:
            st.success(f"✅ SITUATION NORMALE — Taux de fraude : **{taux_fraude:.1f}%** ({fraudes}/{total} transactions)")

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

        # ── KPI ────────────────────────────────────────────────────────────
        st.markdown(f"""
        <div style="display:flex;align-items:center;gap:14px;
            background:linear-gradient(135deg,#111b3d,#0d1530);
            border:2px solid #00d4ff;border-left:5px solid #00d4ff;
            border-radius:12px;padding:1rem 1.5rem;margin:1.5rem 0 1rem 0;
            box-shadow:0 4px 18px rgba(79,123,255,0.18);">
            <span style="font-size:26px;">📈</span>
            <span style="font-size:15px;font-weight:900;color:#ffffff;
                font-family:'Poppins',sans-serif;text-transform:uppercase;
                letter-spacing:1.5px;">KPI — INDICATEURS CLÉS DE PERFORMANCE</span>
            <div style="flex:1;height:1px;background:linear-gradient(90deg,#00d4ff55,transparent);margin-left:8px;"></div>
        </div>
        """, unsafe_allow_html=True)
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown(f'<div class="stat-box"><div class="stat-label">📊 Total</div><div class="stat-value">{total}</div></div>', unsafe_allow_html=True)
        with col2:
            st.markdown(f'<div class="stat-box"><div class="stat-label" style="color:#ff4757;">🚨 Fraudes</div><div class="stat-value" style="color:#ff4757;">{fraudes}</div></div>', unsafe_allow_html=True)
        with col3:
            st.markdown(f'<div class="stat-box"><div class="stat-label" style="color:#ffa502;">⚠️ Suspects</div><div class="stat-value" style="color:#ffa502;">{suspects}</div></div>', unsafe_allow_html=True)
        with col4:
            st.markdown(f'<div class="stat-box"><div class="stat-label" style="color:#2ed573;">✅ Saines</div><div class="stat-value" style="color:#2ed573;">{saines}</div></div>', unsafe_allow_html=True)

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

        # ── GRAPHIQUES ─────────────────────────────────────────────────────
        BG   = "rgba(10,14,39,0.97)"
        PLOT = "rgba(5,9,28,0.97)"
        FONT = dict(color="#ffffff", size=14, family="Poppins")
        AXIS = dict(tickfont=dict(color="#ffffff", size=13), title_font=dict(color="#ffffff", size=14),
                    gridcolor="rgba(79,123,255,0.15)", linecolor="#3a4f6f", zerolinecolor="#3a4f6f")
        MARGIN = dict(t=55, b=55, l=55, r=45)

        st.markdown(f"""
        <div style="display:flex;align-items:center;gap:14px;
            background:linear-gradient(135deg,#111b3d,#0d1530);
            border:2px solid #a78bfa;border-left:5px solid #a78bfa;
            border-radius:12px;padding:1rem 1.5rem;margin:1.5rem 0 1rem 0;
            box-shadow:0 4px 18px rgba(79,123,255,0.18);">
            <span style="font-size:26px;">📊</span>
            <span style="font-size:15px;font-weight:900;color:#ffffff;
                font-family:'Poppins',sans-serif;text-transform:uppercase;
                letter-spacing:1.5px;">RÉPARTITION DES VERDICTS</span>
            <div style="flex:1;height:1px;background:linear-gradient(90deg,#a78bfa55,transparent);margin-left:8px;"></div>
        </div>
        """, unsafe_allow_html=True)
        col1, col2 = st.columns(2)
        with col1:
            fig = go.Figure(go.Bar(
                x=["✅ SAINES","⚠️ SUSPECTS","🚨 FRAUDES"], y=[saines, suspects, fraudes],
                marker=dict(color=["#2ed573","#ffa502","#ff4757"], line=dict(color="#0a0e27",width=2)),
                text=[f"<b>{saines}</b>",f"<b>{suspects}</b>",f"<b>{fraudes}</b>"],
                textposition="outside", textfont=dict(size=15, color="#ffffff"),
                hovertemplate="<b>%{x}</b><br>Nombre: %{y}<extra></extra>",
            ))
            fig.update_layout(title=dict(text="Transactions par verdict", font=dict(color="#ffffff",size=16), x=0.5, xanchor="center"),
                height=380, paper_bgcolor=BG, plot_bgcolor=PLOT, font=FONT, margin=MARGIN,
                xaxis=dict(showgrid=False, tickfont=dict(color="#ffffff",size=14), linecolor="#3a4f6f"),
                yaxis=dict(title="Nombre", **AXIS))
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

        with col2:
            fig = go.Figure(go.Pie(
                labels=["✅ SAINES","⚠️ SUSPECTS","🚨 FRAUDES"], values=[saines, suspects, fraudes],
                marker=dict(colors=["#2ed573","#ffa502","#ff4757"], line=dict(color="#0a0e27",width=3)),
                hole=0.44, textfont=dict(size=14, color="#ffffff"), textinfo="label+percent",
                pull=[0, 0.04, 0.09],
                hovertemplate="<b>%{label}</b><br>Nombre: %{value}<br>Part: %{percent}<extra></extra>",
            ))
            fig.update_layout(title=dict(text="Distribution globale", font=dict(color="#ffffff",size=16), x=0.5, xanchor="center"),
                height=380, paper_bgcolor=BG, font=FONT, margin=MARGIN,
                legend=dict(font=dict(color="#ffffff",size=13), bgcolor="rgba(17,27,61,0.85)", bordercolor="#3a4f6f", borderwidth=1))
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

        # ── Évolution scores ───────────────────────────────────────────────
        st.markdown(f"""
        <div style="display:flex;align-items:center;gap:14px;
            background:linear-gradient(135deg,#111b3d,#0d1530);
            border:2px solid #2ed573;border-left:5px solid #2ed573;
            border-radius:12px;padding:1rem 1.5rem;margin:1.5rem 0 1rem 0;
            box-shadow:0 4px 18px rgba(79,123,255,0.18);">
            <span style="font-size:26px;">📈</span>
            <span style="font-size:15px;font-weight:900;color:#ffffff;
                font-family:'Poppins',sans-serif;text-transform:uppercase;
                letter-spacing:1.5px;">ÉVOLUTION DU SCORE DE RISQUE</span>
            <div style="flex:1;height:1px;background:linear-gradient(90deg,#2ed57355,transparent);margin-left:8px;"></div>
        </div>
        """, unsafe_allow_html=True)
        col1, col2 = st.columns([2, 1])
        with col1:
            ids = [e["id"] for e in st.session_state.historique]
            scores = [e["score"] for e in st.session_state.historique]
            pts_col = ["#ff4757" if s > seuil_fraude else "#ffa502" if s > seuil_suspect else "#2ed573" for s in scores]
            fig = go.Figure()
            fig.add_hrect(y0=seuil_fraude, y1=110, fillcolor="rgba(255,71,87,0.05)", line_width=0)
            fig.add_hrect(y0=seuil_suspect, y1=seuil_fraude, fillcolor="rgba(255,165,2,0.04)", line_width=0)
            fig.add_trace(go.Scatter(x=ids, y=scores, mode="lines+markers", name="Score de risque",
                line=dict(color="#4f7bff", width=3),
                marker=dict(size=11, color=pts_col, line=dict(color="#ffffff", width=2)),
                fill="tozeroy", fillcolor="rgba(79,123,255,0.07)",
                hovertemplate="<b>Analyse #%{x}</b><br>Score: %{y:.1f}%<extra></extra>"))
            fig.add_hline(y=seuil_fraude, line_dash="dash", line_color="#ff4757", line_width=2,
                annotation=dict(text=f"🚨 FRAUDE {seuil_fraude}%", font=dict(color="#ff4757",size=12), bgcolor="rgba(255,71,87,0.15)"))
            fig.add_hline(y=seuil_suspect, line_dash="dash", line_color="#ffa502", line_width=2,
                annotation=dict(text=f"⚠️ SUSPECT {seuil_suspect}%", font=dict(color="#ffa502",size=12), bgcolor="rgba(255,165,2,0.15)"))
            fig.update_layout(title=dict(text="Évolution temporelle des scores", font=dict(color="#ffffff",size=16), x=0.5, xanchor="center"),
                height=380, paper_bgcolor=BG, plot_bgcolor=PLOT, font=FONT, margin=MARGIN,
                xaxis=dict(title="N° Analyse", **AXIS), yaxis=dict(title="Score (%)", range=[0,112], **AXIS),
                hovermode="x unified")
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

        with col2:
            fig = go.Figure(go.Indicator(
                mode="gauge+number+delta", value=score_moy,
                delta=dict(reference=50, increasing=dict(color="#ff4757"), decreasing=dict(color="#2ed573"), font=dict(size=14,color="#ffffff")),
                number=dict(suffix="%", font=dict(size=40, color="#ffffff")),
                title=dict(text="SCORE MOYEN GLOBAL", font=dict(size=14, color="#ffffff")),
                gauge=dict(
                    axis=dict(range=[0,100], tickwidth=2, tickcolor="#ffffff", tickfont=dict(color="#ffffff",size=12)),
                    bar=dict(color="#4f7bff", thickness=0.28),
                    bgcolor="rgba(0,0,0,0)", borderwidth=0,
                    steps=[dict(range=[0,seuil_suspect], color="rgba(46,213,115,0.18)"),
                           dict(range=[seuil_suspect,seuil_fraude], color="rgba(255,165,2,0.18)"),
                           dict(range=[seuil_fraude,100], color="rgba(255,71,87,0.18)")],
                    threshold=dict(line=dict(color="#ff4757",width=4), thickness=0.85, value=seuil_fraude),
                )
            ))
            fig.update_layout(height=380, paper_bgcolor=BG, font=FONT, margin=dict(t=55,b=25,l=20,r=20))
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

        # ── CARTE GÉOGRAPHIQUE CI ──────────────────────────────────────────
        st.markdown(f"""
        <div style="display:flex;align-items:center;gap:14px;
            background:linear-gradient(135deg,#111b3d,#0d1530);
            border:2px solid #ffa502;border-left:5px solid #ffa502;
            border-radius:12px;padding:1rem 1.5rem;margin:1.5rem 0 1rem 0;
            box-shadow:0 4px 18px rgba(79,123,255,0.18);">
            <span style="font-size:26px;">🌍</span>
            <span style="font-size:15px;font-weight:900;color:#ffffff;
                font-family:'Poppins',sans-serif;text-transform:uppercase;
                letter-spacing:1.5px;">CARTE DE RISQUE GÉOGRAPHIQUE — CÔTE D'IVOIRE (simulée)</span>
            <div style="flex:1;height:1px;background:linear-gradient(90deg,#ffa50255,transparent);margin-left:8px;"></div>
        </div>
        """, unsafe_allow_html=True)

        np.random.seed(42)
        villes_ci = {
            "Abidjan": {"lat": 5.354, "lon": -4.008, "pop": 0.45},
            "Bouaké": {"lat": 7.69, "lon": -5.03, "pop": 0.12},
            "Daloa": {"lat": 6.877, "lon": -6.45, "pop": 0.08},
            "San-Pédro": {"lat": 4.748, "lon": -6.636, "pop": 0.07},
            "Korhogo": {"lat": 9.458, "lon": -5.629, "pop": 0.06},
            "Man": {"lat": 7.412, "lon": -7.554, "pop": 0.05},
            "Yamoussoukro": {"lat": 6.821, "lon": -5.274, "pop": 0.06},
            "Gagnoa": {"lat": 6.133, "lon": -5.95, "pop": 0.05},
            "Abengourou": {"lat": 6.729, "lon": -3.496, "pop": 0.04},
            "Divo": {"lat": 5.836, "lon": -5.357, "pop": 0.02},
        }

        # Simulation basée sur le taux global + aléatoire pondéré
        geo_data = []
        total_fraudes_sim = max(fraudes, 1)
        for ville, info in villes_ci.items():
            nb_fraudes_sim = max(0, int(total_fraudes_sim * info["pop"] + np.random.randint(-1, 3)))
            risk_score = min(100, nb_fraudes_sim * 20 + np.random.randint(5, 30))
            geo_data.append({
                "Ville": ville, "Latitude": info["lat"], "Longitude": info["lon"],
                "Fraudes simulées": nb_fraudes_sim, "Score risque": risk_score
            })

        df_geo = pd.DataFrame(geo_data)

        fig_map = px.scatter_mapbox(
            df_geo, lat="Latitude", lon="Longitude",
            size="Score risque", color="Score risque",
            hover_name="Ville",
            hover_data={"Fraudes simulées": True, "Score risque": True, "Latitude": False, "Longitude": False},
            color_continuous_scale=["#2ed573", "#ffa502", "#ff4757"],
            size_max=50, zoom=5.5,
            center={"lat": 7.0, "lon": -5.5},
            mapbox_style="carto-darkmatter",
            title="🗺️ Concentration de risques par région (simulation)"
        )
        fig_map.update_layout(
            height=450, paper_bgcolor="rgba(10,14,39,0.97)",
            font=dict(color="#ffffff", family="Poppins"),
            title_font=dict(color="#ffffff", size=16),
            margin=dict(t=50, b=10, l=10, r=10),
            coloraxis_colorbar=dict(title="Score", tickfont=dict(color="#fff"), title_font=dict(color="#fff"))
        )
        st.plotly_chart(fig_map, use_container_width=True, config={"displayModeBar": False})

        st.caption("⚠️ Données géographiques simulées à des fins de démonstration.")

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

        # ── ANALYSE FINANCIÈRE ─────────────────────────────────────────────
        st.markdown(f"""
        <div style="display:flex;align-items:center;gap:14px;
            background:linear-gradient(135deg,#111b3d,#0d1530);
            border:2px solid #2ed573;border-left:5px solid #2ed573;
            border-radius:12px;padding:1rem 1.5rem;margin:1.5rem 0 1rem 0;
            box-shadow:0 4px 18px rgba(79,123,255,0.18);">
            <span style="font-size:26px;">💰</span>
            <span style="font-size:15px;font-weight:900;color:#ffffff;
                font-family:'Poppins',sans-serif;text-transform:uppercase;
                letter-spacing:1.5px;">ANALYSE FINANCIÈRE & DISTRIBUTION</span>
            <div style="flex:1;height:1px;background:linear-gradient(90deg,#2ed57355,transparent);margin-left:8px;"></div>
        </div>
        """, unsafe_allow_html=True)
        col1, col2 = st.columns(2)
        with col1:
            mv = df.groupby("verdict")["montant"].sum().reset_index()
            cmap = {"SAINE":"#2ed573","SUSPECT":"#ffa502","FRAUDE":"#ff4757"}
            fig = go.Figure(go.Bar(
                x=mv["verdict"], y=mv["montant"],
                marker=dict(color=[cmap.get(v,"#4f7bff") for v in mv["verdict"]], line=dict(width=2,color="#0a0e27")),
                text=[f"{v:,.0f} F" for v in mv["montant"]], textposition="outside",
                textfont=dict(color="#ffffff", size=12),
                hovertemplate="<b>%{x}</b><br>Volume: %{y:,.0f} FCFA<extra></extra>"))
            fig.update_layout(title=dict(text="Volume financier par verdict (FCFA)", font=dict(color="#ffffff",size=16), x=0.5, xanchor="center"),
                height=340, paper_bgcolor=BG, plot_bgcolor=PLOT, font=FONT, margin=MARGIN,
                xaxis=dict(showgrid=False, tickfont=dict(color="#ffffff",size=14), linecolor="#3a4f6f"),
                yaxis=dict(title="Montant (FCFA)", **AXIS))
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        with col2:
            fig = go.Figure(go.Box(y=df["score"], name="Scores", boxmean="sd",
                marker=dict(color="#4f7bff", size=8), line=dict(color="#4f7bff", width=2),
                fillcolor="rgba(79,123,255,0.15)", hovertemplate="Score: %{y:.1f}%<extra></extra>"))
            fig.update_layout(title=dict(text="Distribution des scores de risque", font=dict(color="#ffffff",size=16), x=0.5, xanchor="center"),
                height=340, paper_bgcolor=BG, plot_bgcolor=PLOT, font=FONT, margin=MARGIN,
                yaxis=dict(title="Score (%)", range=[0,105], **AXIS), xaxis=dict(tickfont=dict(color="#ffffff")))
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

        # ── STATS AVANCÉES ─────────────────────────────────────────────────
        st.markdown(f"""
        <div style="display:flex;align-items:center;gap:14px;
            background:linear-gradient(135deg,#111b3d,#0d1530);
            border:2px solid #ff6b9d;border-left:5px solid #ff6b9d;
            border-radius:12px;padding:1rem 1.5rem;margin:1.5rem 0 1rem 0;
            box-shadow:0 4px 18px rgba(79,123,255,0.18);">
            <span style="font-size:26px;">🔬</span>
            <span style="font-size:15px;font-weight:900;color:#ffffff;
                font-family:'Poppins',sans-serif;text-transform:uppercase;
                letter-spacing:1.5px;">STATISTIQUES AVANCÉES</span>
            <div style="flex:1;height:1px;background:linear-gradient(90deg,#ff6b9d55,transparent);margin-left:8px;"></div>
        </div>
        """, unsafe_allow_html=True)
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"""
            <div class="card-premium">
                <div class="card-title">💰 ANALYSE DES MONTANTS</div>
                <div style="font-size:15px; line-height:2.5; color:#e0e7ff;">
                    <div><span style="color:#a0aec0;">VOLUME TOTAL:</span> <span style="color:#fff; font-weight:800;">{montant_total:,.0f} FCFA</span></div>
                    <div><span style="color:#a0aec0;">MONTANT MOYEN:</span> <span style="color:#fff; font-weight:800;">{montant_moyen:,.0f} FCFA</span></div>
                    <div><span style="color:#a0aec0;">À RISQUE:</span> <span style="color:#ff4757; font-weight:800;">{df[df.verdict != 'SAINE'].montant.sum():,.0f} FCFA</span></div>
                    <div><span style="color:#a0aec0;">PERTES ÉVITÉES EST.:</span> <span style="color:#2ed573; font-weight:800;">{pertes_evitees:,.0f} FCFA</span></div>
                    <div><span style="color:#a0aec0;">MONTANT MIN:</span> <span style="color:#fff; font-weight:800;">{df.montant.min():,.0f} FCFA</span></div>
                    <div><span style="color:#a0aec0;">MONTANT MAX:</span> <span style="color:#fff; font-weight:800;">{df.montant.max():,.0f} FCFA</span></div>
                </div>
            </div>""", unsafe_allow_html=True)
        with col2:
            st.markdown(f"""
            <div class="card-premium">
                <div class="card-title">🎯 MÉTRIQUES CLÉS</div>
                <div style="font-size:15px; line-height:2.5; color:#e0e7ff;">
                    <div><span style="color:#a0aec0;">SCORE MOYEN:</span> <span style="color:#fff; font-weight:800;">{score_moy:.1f}%</span></div>
                    <div><span style="color:#a0aec0;">TAUX FRAUDE:</span> <span style="color:#ff4757; font-weight:800;">{taux_fraude:.1f}%</span></div>
                    <div><span style="color:#a0aec0;">SCORE MIN:</span> <span style="color:#fff; font-weight:800;">{df.score.min():.1f}%</span></div>
                    <div><span style="color:#a0aec0;">SCORE MAX:</span> <span style="color:#fff; font-weight:800;">{df.score.max():.1f}%</span></div>
                    <div><span style="color:#a0aec0;">ÉCART-TYPE:</span> <span style="color:#4f7bff; font-weight:800;">{df.score.std():.1f}%</span></div>
                    <div><span style="color:#a0aec0;">SCORE SANTÉ:</span> <span style="color:{grade_col}; font-weight:800;">{grade} — {grade_desc}</span></div>
                </div>
            </div>""", unsafe_allow_html=True)

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
        st.markdown(f"""
        <div style="display:flex;align-items:center;gap:14px;
            background:linear-gradient(135deg,#111b3d,#0d1530);
            border:2px solid #00d4ff;border-left:5px solid #00d4ff;
            border-radius:12px;padding:1rem 1.5rem;margin:1.5rem 0 1rem 0;
            box-shadow:0 4px 18px rgba(79,123,255,0.18);">
            <span style="font-size:26px;">📋</span>
            <span style="font-size:15px;font-weight:900;color:#ffffff;
                font-family:'Poppins',sans-serif;text-transform:uppercase;
                letter-spacing:1.5px;">VUE DÉTAILLÉE COMPLÈTE</span>
            <div style="flex:1;height:1px;background:linear-gradient(90deg,#00d4ff55,transparent);margin-left:8px;"></div>
        </div>
        """, unsafe_allow_html=True)
        df_view = df[["id","date","libelle","montant","verdict","score"]].copy()
        df_view.columns = ["ID","DATE","DESCRIPTION","MONTANT (FCFA)","VERDICT","SCORE (%)"]
        st.dataframe(df_view, use_container_width=True, hide_index=True)

# ╔═════════════════════════════════════════════════════════════════════════════╗
# ║ ONGLET 4 - ANALYSE EN LOT (BATCH)                                           ║
# ╚═════════════════════════════════════════════════════════════════════════════╝
with tab4:
    st.markdown("""
    <div class="card-premium animate-in">
        <div class="card-title">📁 ANALYSE EN LOT — UPLOAD CSV</div>
        <div class="card-subtitle">Uploadez un fichier CSV contenant plusieurs transactions et analysez-les toutes d'un coup</div>
    </div>
    """, unsafe_allow_html=True)

    # Instructions format CSV
    with st.expander("📖 FORMAT CSV ATTENDU — Cliquez pour voir les instructions"):
        st.markdown("""
        **Colonnes requises dans votre CSV :**

        | Colonne | Description | Exemple |
        |---------|-------------|---------|
        | `montant` | Montant FCFA | 15000.0 |
        | `horodatage` | Secondes depuis minuit | 43200.0 |
        | `libelle` | Description (optionnel) | Achat mobile |
        | `V1` à `V28` | Composantes PCA (optionnel, 0 par défaut) | 0.5 |

        **Exemple de ligne CSV :**
        ```
        montant,horodatage,libelle,V1,V2,...,V28
        5000,43200,Achat en ligne,0.1,-0.5,...,0.0
        ```
        """)
        # Bouton télécharger template
        template_df = pd.DataFrame({
            "montant": [5000.0, 150000.0, 800.0],
            "horodatage": [43200.0, 3600.0, 86399.0],
            "libelle": ["Achat mobile", "Virement suspect", "Retrait ATM"],
            **{f"V{i}": [0.0, 0.0, 0.0] for i in range(1, 29)}
        })
        template_csv = template_df.to_csv(index=False).encode('utf-8')
        st.markdown("""
        <style>
        div[data-testid="stDownloadButton"] > button {
            background: linear-gradient(135deg, #4f7bff 0%, #00d4ff 100%) !important;
            color: #ffffff !important;
            font-weight: 900 !important;
            font-size: 14px !important;
            border: none !important;
            border-radius: 10px !important;
            padding: 0.7rem 1.6rem !important;
            letter-spacing: 1px !important;
            box-shadow: 0 4px 16px rgba(79,123,255,0.5) !important;
        }
        div[data-testid="stDownloadButton"] > button:hover {
            transform: translateY(-2px) !important;
            box-shadow: 0 8px 24px rgba(79,123,255,0.65) !important;
        }
        </style>
        """, unsafe_allow_html=True)
        st.download_button("⬇️ Télécharger le template CSV", template_csv, "template_trustlink.csv", "text/csv")

    uploaded_file = st.file_uploader("📂 IMPORTER VOTRE FICHIER CSV", type=["csv"], help="Format CSV avec colonnes: montant, horodatage, V1-V28 (optionnel: libelle)")

    if uploaded_file is not None and modele is not None:
        try:
            df_batch = pd.read_csv(uploaded_file)
            st.success(f"✅ Fichier chargé : **{len(df_batch)} transactions** détectées")

            # Validation colonnes
            required_cols = ["montant", "horodatage"]
            missing = [c for c in required_cols if c not in df_batch.columns]
            if missing:
                st.error(f"❌ Colonnes manquantes : {missing}")
            else:
                # Compléter avec 0 les colonnes V manquantes
                for i in range(1, 29):
                    if f"V{i}" not in df_batch.columns:
                        df_batch[f"V{i}"] = 0.0

                if "libelle" not in df_batch.columns:
                    df_batch["libelle"] = [f"Transaction #{i+1}" for i in range(len(df_batch))]

                if st.button("🚀 LANCER L'ANALYSE EN LOT", use_container_width=True, type="primary"):
                    progress_bar = st.progress(0)
                    resultats = []
                    n = len(df_batch)

                    for idx, row in df_batch.iterrows():
                        vecs = [row.get(f"V{i}", 0.0) for i in range(1, 29)]
                        entree = np.array([row["horodatage"]] + vecs + [row["montant"]]).reshape(1, -1)
                        entree_scaled = scaler.transform(entree)
                        proba = modele.predict_proba(entree_scaled)[0][1]
                        score = proba * 100
                        pred = modele.predict(entree_scaled)[0]

                        if score > seuil_fraude:
                            verdict = "FRAUDE"
                        elif score > seuil_suspect:
                            verdict = "SUSPECT"
                        else:
                            verdict = "SAINE"

                        resultats.append({
                            "N°": idx + 1,
                            "Description": str(row["libelle"])[:40],
                            "Montant (FCFA)": row["montant"],
                            "Score (%)": round(score, 2),
                            "Verdict": verdict,
                            "Prédiction ML": "FRAUDE" if pred == 1 else "LÉGITIME",
                        })
                        progress_bar.progress((idx + 1) / n)

                    df_resultats = pd.DataFrame(resultats)
                    nb_fraudes_b = sum(1 for r in resultats if r["Verdict"] == "FRAUDE")
                    nb_suspects_b = sum(1 for r in resultats if r["Verdict"] == "SUSPECT")
                    nb_saines_b = sum(1 for r in resultats if r["Verdict"] == "SAINE")

                    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
                    st.markdown("### 📊 RÉSULTATS DE L'ANALYSE EN LOT")

                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.markdown(f'<div class="stat-box"><div class="stat-label">📊 Total</div><div class="stat-value">{n}</div></div>', unsafe_allow_html=True)
                    with col2:
                        st.markdown(f'<div class="stat-box"><div class="stat-label" style="color:#ff4757;">🚨 Fraudes</div><div class="stat-value" style="color:#ff4757;">{nb_fraudes_b}</div></div>', unsafe_allow_html=True)
                    with col3:
                        st.markdown(f'<div class="stat-box"><div class="stat-label" style="color:#ffa502;">⚠️ Suspects</div><div class="stat-value" style="color:#ffa502;">{nb_suspects_b}</div></div>', unsafe_allow_html=True)
                    with col4:
                        st.markdown(f'<div class="stat-box"><div class="stat-label" style="color:#2ed573;">✅ Saines</div><div class="stat-value" style="color:#2ed573;">{nb_saines_b}</div></div>', unsafe_allow_html=True)

                    st.markdown("<br>", unsafe_allow_html=True)

                    # Tableau résultats avec couleurs
                    def color_verdict(val):
                        if val == "FRAUDE":
                            return "background-color: rgba(255,71,87,0.15); color: #ff4757; font-weight: bold;"
                        elif val == "SUSPECT":
                            return "background-color: rgba(255,165,2,0.15); color: #ffa502; font-weight: bold;"
                        else:
                            return "background-color: rgba(46,213,115,0.15); color: #2ed573; font-weight: bold;"

                    st.dataframe(
                        df_resultats.style.applymap(color_verdict, subset=["Verdict"]),
                        use_container_width=True, hide_index=True
                    )

                    # Export des résultats
                    st.markdown("<br>", unsafe_allow_html=True)
                    col_exp1, col_exp2 = st.columns(2)
                    with col_exp1:
                        csv_res = df_resultats.to_csv(index=False).encode('utf-8')
                        st.download_button("📥 EXPORTER RÉSULTATS CSV", csv_res, "batch_resultats.csv", "text/csv", use_container_width=True)
                    with col_exp2:
                        # Ajouter au session state
                        if st.button("➕ AJOUTER À L'HISTORIQUE PRINCIPAL", use_container_width=True):
                            for r in resultats:
                                st.session_state.historique.append({
                                    "id": len(st.session_state.historique) + 1,
                                    "date": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                                    "libelle": r["Description"],
                                    "montant": r["Montant (FCFA)"],
                                    "verdict": r["Verdict"],
                                    "score": r["Score (%)"],
                                    "prediction": 1 if r["Prédiction ML"] == "FRAUDE" else 0,
                                    "notes": "Import batch",
                                    "vecteurs": [0.0] * 28,
                                    "horodatage": 0.0,
                                })
                            st.success(f"✅ {n} transactions ajoutées à l'historique !")
                            st.rerun()

                    # Mini graphique récap
                    fig_b = go.Figure(go.Pie(
                        labels=["✅ SAINES","⚠️ SUSPECTS","🚨 FRAUDES"],
                        values=[nb_saines_b, nb_suspects_b, nb_fraudes_b],
                        marker=dict(colors=["#2ed573","#ffa502","#ff4757"], line=dict(color="#0a0e27",width=3)),
                        hole=0.5, textfont=dict(size=14, color="#ffffff"), textinfo="label+percent",
                        pull=[0, 0.04, 0.09],
                    ))
                    BG2 = "rgba(10,14,39,0.97)"
                    fig_b.update_layout(
                        title=dict(text=f"Résumé batch — {n} transactions", font=dict(color="#ffffff",size=16), x=0.5, xanchor="center"),
                        height=350, paper_bgcolor=BG2, font=dict(color="#ffffff", size=14, family="Poppins"),
                        margin=dict(t=55,b=25,l=20,r=20),
                        legend=dict(font=dict(color="#ffffff",size=13), bgcolor="rgba(17,27,61,0.85)", bordercolor="#3a4f6f", borderwidth=1)
                    )
                    st.plotly_chart(fig_b, use_container_width=True, config={"displayModeBar": False})

                    if nb_fraudes_b == 0 and n >= 10:
                        st.balloons()
                        st.success("🎉 Aucune fraude détectée dans ce lot de transactions !")

        except Exception as e:
            st.error(f"❌ Erreur lors de la lecture du fichier : {str(e)}")
            st.info("Vérifiez que votre fichier CSV correspond au format attendu (colonnes : montant, horodatage, V1-V28).")
    elif uploaded_file is None:
        components.html("""
        <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@600;700;800;900&display=swap" rel="stylesheet">
        <div style="text-align:center; padding:3rem 2rem; background:linear-gradient(135deg,#111b3d,#0d1530);
            border:2px dashed #3a4f6f; border-radius:16px; font-family:'Poppins',sans-serif; margin-top:1rem;">
            <div style="font-size:52px; margin-bottom:1rem;">📁</div>
            <h3 style="color:#ffffff; margin:0 0 0.8rem; font-size:20px; font-weight:900; text-transform:uppercase;">AUCUN FICHIER SÉLECTIONNÉ</h3>
            <p style="color:#a0aec0; font-size:13px; font-weight:600; max-width:400px; margin:0 auto; line-height:1.7;">
                Importez un fichier CSV pour analyser plusieurs transactions simultanément.<br>
                Téléchargez d'abord le <strong style="color:#4f7bff;">template CSV</strong> ci-dessus pour connaître le format attendu.
            </p>
        </div>
        """, height=240)


# ╔═════════════════════════════════════════════════════════════════════════════╗
# ║ ONGLET GUIDE - DOCUMENTATION COMPLÈTE                                       ║
# ╚═════════════════════════════════════════════════════════════════════════════╝
with tab_guide:
    st.markdown("""
    <style>
    .guide-section {
        background: linear-gradient(135deg, #111b3d, #192551);
        border: 2px solid #2a3f5f;
        border-radius: 16px;
        padding: 1.8rem 2rem;
        margin-bottom: 1.5rem;
    }
    .guide-title {
        font-size: 20px;
        font-weight: 900;
        color: #ffffff;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        margin-bottom: 1rem;
        border-bottom: 2px solid #4f7bff;
        padding-bottom: 0.6rem;
    }
    .guide-tab-card {
        background: rgba(79,123,255,0.08);
        border: 1.5px solid #4f7bff;
        border-left: 5px solid #4f7bff;
        border-radius: 12px;
        padding: 1rem 1.2rem;
        margin-bottom: 1rem;
    }
    .guide-tab-name {
        font-size: 16px;
        font-weight: 900;
        color: #00e5ff;
        margin-bottom: 0.4rem;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    .guide-tab-desc {
        font-size: 13px;
        color: #c0d4f0;
        font-weight: 600;
        line-height: 1.7;
    }
    .guide-v-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
        gap: 0.7rem;
        margin-top: 0.8rem;
    }
    .guide-v-card {
        background: rgba(0,212,255,0.05);
        border: 1.5px solid #1e3a5f;
        border-radius: 10px;
        padding: 0.7rem 0.9rem;
    }
    .guide-v-label {
        font-size: 12px;
        font-weight: 900;
        color: #4f7bff;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        margin-bottom: 0.2rem;
    }
    .guide-v-text {
        font-size: 12px;
        color: #a0bfff;
        font-weight: 600;
        line-height: 1.5;
    }
    .guide-feat-row {
        display: flex;
        align-items: flex-start;
        gap: 0.8rem;
        background: rgba(46,213,115,0.05);
        border: 1.5px solid #1e4a35;
        border-radius: 10px;
        padding: 0.8rem 1rem;
        margin-bottom: 0.7rem;
    }
    .guide-feat-icon { font-size: 20px; flex-shrink: 0; margin-top: 2px; }
    .guide-feat-body { flex: 1; }
    .guide-feat-title { font-size: 13px; font-weight: 900; color: #2ed573; text-transform: uppercase; letter-spacing: 0.8px; }
    .guide-feat-desc { font-size: 12px; color: #a0c0aa; font-weight: 600; line-height: 1.5; margin-top: 0.2rem; }
    </style>
    """, unsafe_allow_html=True)

    # ── Hero guide ────────────────────────────────────────────────────────────
    st.markdown("""
    <div style="background:radial-gradient(ellipse at 50% 0%, #0d2280 0%, #050d3a 60%, #020818 100%);
        border:1.5px solid #1e3070; border-radius:18px; padding:2rem 2rem 1.5rem;
        text-align:center; margin-bottom:1.5rem;">
        <div style="font-size:48px; margin-bottom:0.6rem;">📖</div>
        <h2 style="font-family:'Poppins',sans-serif; font-size:26px; font-weight:900;
            color:#ffffff; margin:0; text-transform:uppercase; letter-spacing:2px;">
            GUIDE UTILISATEUR
        </h2>
        <p style="color:#00e5ff; font-size:14px; font-weight:700; margin:0.5rem 0 0;">
            Hemerson TrustLink v5.0 — Documentation complète
        </p>
    </div>
    """, unsafe_allow_html=True)

    # ── Section 1 : Les onglets ───────────────────────────────────────────────
    st.markdown('<div class="guide-section">', unsafe_allow_html=True)
    st.markdown('<div class="guide-title">🗂️ Description des onglets</div>', unsafe_allow_html=True)

    st.markdown("""
    <div class="guide-tab-card">
        <div class="guide-tab-name">🔍 Analyser Transaction</div>
        <div class="guide-tab-desc">
            C'est l'onglet principal de l'application. Vous y saisissez les données d'une transaction
            (montant, horodatage, description et les 28 vecteurs V1–V28) puis vous cliquez sur
            <strong style="color:#fff;">ANALYSER</strong> pour obtenir instantanément un verdict du modèle IA :
            <strong style="color:#2ed573;">SAINE</strong>,
            <strong style="color:#ffa502;">SUSPECTE</strong> ou
            <strong style="color:#ff4757;">FRAUDE</strong>, accompagné d'un score de risque en pourcentage.
            Vous pouvez aussi ajouter des notes d'analyste et exporter le rapport en PDF.
        </div>
    </div>

    <div class="guide-tab-card" style="border-left-color:#2ed573; border-color:#2ed573;">
        <div class="guide-tab-name" style="color:#2ed573;">📋 Historique</div>
        <div class="guide-tab-desc">
            Affiche toutes les transactions analysées pendant votre session en cours.
            Chaque entrée montre le label de la transaction, son verdict, son score IA, la date/heure
            et les notes éventuelles. Vous pouvez marquer une transaction comme <strong style="color:#ff0080;">critique</strong>,
            télécharger l'historique complet en CSV, ou vider l'historique.
        </div>
    </div>

    <div class="guide-tab-card" style="border-left-color:#ffa502; border-color:#ffa502;">
        <div class="guide-tab-name" style="color:#ffa502;">📊 Tableau de bord</div>
        <div class="guide-tab-desc">
            Vue d'ensemble analytique de toutes vos transactions de la session. Vous y trouvez :
            les statistiques globales (total, fraudes, suspects, saines), un graphique en camembert
            de la répartition, un graphique en barres des montants par verdict, la liste des
            transactions critiques marquées, le <strong style="color:#fff;">score santé du portefeuille</strong> (note A/B/C/D),
            une estimation des pertes financières évitées, et une carte de risque géographique
            pour la Côte d'Ivoire.
        </div>
    </div>

    <div class="guide-tab-card" style="border-left-color:#a78bfa; border-color:#a78bfa;">
        <div class="guide-tab-name" style="color:#a78bfa;">📁 Analyse en lot</div>
        <div class="guide-tab-desc">
            Permet d'analyser plusieurs transactions en une seule opération. Importez un fichier
            CSV dont chaque ligne correspond à une transaction (colonnes requises :
            <strong style="color:#fff;">montant</strong>, <strong style="color:#fff;">horodatage</strong>, <strong style="color:#fff;">V1 à V28</strong>).
            L'application analyse toutes les lignes, affiche un résumé, colorie les résultats
            et vous permet de télécharger les résultats enrichis.
            Un template CSV est disponible au téléchargement pour vous guider.
        </div>
    </div>

    <div class="guide-tab-card" style="border-left-color:#00e5ff; border-color:#00e5ff;">
        <div class="guide-tab-name" style="color:#00e5ff;">📖 Guide (cet onglet)</div>
        <div class="guide-tab-desc">
            Documentation complète de l'application : explication de chaque onglet,
            description des 28 vecteurs PCA (V1–V28), et présentation des fonctionnalités
            importantes de Hemerson TrustLink v5.0.
        </div>
    </div>

    <div class="guide-tab-card" style="border-left-color:#7c3aed; border-color:#7c3aed;">
        <div class="guide-tab-name" style="color:#a78bfa;">🔐 Admin <span style="font-size:11px; color:#7c8db5;">(réservé administrateur)</span></div>
        <div class="guide-tab-desc">
            Onglet visible uniquement par l'administrateur. Il affiche les statistiques
            de fréquentation (utilisateurs uniques, connexions Google, connexions totales),
            la liste complète des utilisateurs connectés avec leurs informations (email, rôle,
            type de connexion, date/heure de première et dernière connexion), ainsi que des
            outils pour exporter ou effacer les logs.
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

    # ── Section 2 : Variables V1–V28 ─────────────────────────────────────────
    st.markdown('<div class="guide-section">', unsafe_allow_html=True)
    st.markdown('<div class="guide-title">🧬 Les variables V1 à V28 — Vecteurs PCA</div>', unsafe_allow_html=True)
    st.markdown("""
    <p style="color:#a0bfff; font-size:13px; font-weight:600; line-height:1.7; margin-bottom:1rem;">
        Les variables <strong style="color:#fff;">V1 à V28</strong> sont des <strong style="color:#00e5ff;">composantes d'analyse en composantes principales (PCA)</strong>
        générées automatiquement à partir des données transactionnelles brutes (données sensibles
        comme le numéro de carte, le commerçant, etc.). Elles sont anonymisées pour protéger
        la confidentialité, et c'est sur ces 28 vecteurs que le modèle Machine Learning effectue
        sa détection. En pratique, si vous recevez des données de votre système bancaire, ces
        valeurs sont déjà calculées et prêtes à saisir.
    </p>
    <div class="guide-v-grid">
    """, unsafe_allow_html=True)

    v_descriptions = {
        1: "Distance temporelle de la transaction par rapport au centroïde PCA",
        2: "Anomalie sur le volume de la transaction",
        3: "Comportement du commerçant (merchant behavior)",
        4: "Fréquence d'utilisation de la carte",
        5: "Localisation géographique encodée",
        6: "Historique du titulaire de la carte",
        7: "Heure normalisée de la journée",
        8: "Type de terminal utilisé",
        9: "Secteur commercial (catégorie marchande)",
        10: "Montant relatif moyen habituel",
        11: "Ratio transactions récentes / historique",
        12: "Distance au dernier achat (temps)",
        13: "Changement de pays ou de région",
        14: "Score de vieillissement du compte",
        15: "Indicateur de fraude passée détectée",
        16: "Cohérence des achats avec le profil",
        17: "Réseau de transactions liées entre elles",
        18: "Vitesse entre deux transactions successives",
        19: "Anomalie de montant par catégorie de dépense",
        20: "Profil démographique encodé du titulaire",
        21: "Indicateur d'activité nocturne (0h–5h)",
        22: "Cohérence du canal de paiement utilisé",
        23: "Volatilité du solde du compte",
        24: "Nombre de transactions refusées récentes",
        25: "Écart par rapport au budget habituel",
        26: "Ratio achat en ligne / achat physique",
        27: "Indicateur multi-comptes (même utilisateur)",
        28: "Signature comportementale résiduelle",
    }

    cards_html = ""
    for i in range(1, 29):
        cards_html += f"""
        <div class="guide-v-card">
            <div class="guide-v-label">V{i}</div>
            <div class="guide-v-text">{v_descriptions[i]}</div>
        </div>"""

    st.markdown(cards_html + '</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

    # ── Section 3 : Fonctionnalités importantes ───────────────────────────────
    st.markdown('<div class="guide-section">', unsafe_allow_html=True)
    st.markdown('<div class="guide-title">⭐ Fonctionnalités importantes</div>', unsafe_allow_html=True)

    st.markdown("""
    <div class="guide-feat-row">
        <div class="guide-feat-icon">🎯</div>
        <div class="guide-feat-body">
            <div class="guide-feat-title">Seuils personnalisables</div>
            <div class="guide-feat-desc">Dans la barre latérale gauche, vous pouvez ajuster les seuils de détection :
            le seuil <strong style="color:#ffa502;">SUSPECT</strong> (par défaut 50%) et le seuil
            <strong style="color:#ff4757;">FRAUDE</strong> (par défaut 75%). Tout score entre les deux sera suspect,
            au-dessus sera fraude, en dessous sera saine.</div>
        </div>
    </div>

    <div class="guide-feat-row">
        <div class="guide-feat-icon">📊</div>
        <div class="guide-feat-body">
            <div class="guide-feat-title">Score santé portefeuille (A / B / C / D)</div>
            <div class="guide-feat-desc">Visible dans le Tableau de bord. Il évalue la qualité globale du portefeuille de transactions :
            <strong style="color:#2ed573;">A</strong> = excellent (très peu de fraudes),
            <strong style="color:#4f7bff;">B</strong> = bon,
            <strong style="color:#ffa502;">C</strong> = attention,
            <strong style="color:#ff4757;">D</strong> = critique (taux de fraude élevé).</div>
        </div>
    </div>

    <div class="guide-feat-row">
        <div class="guide-feat-icon">🚨</div>
        <div class="guide-feat-body">
            <div class="guide-feat-title">Marquer une transaction critique</div>
            <div class="guide-feat-desc">Dans l'onglet Historique, vous pouvez marquer n'importe quelle transaction
            comme <strong style="color:#ff0080;">critique</strong>. Les transactions critiques sont ensuite
            regroupées dans le Tableau de bord pour un suivi prioritaire.</div>
        </div>
    </div>

    <div class="guide-feat-row">
        <div class="guide-feat-icon">📄</div>
        <div class="guide-feat-body">
            <div class="guide-feat-title">Export PDF professionnel</div>
            <div class="guide-feat-desc">Après chaque analyse, un bouton permet de télécharger un rapport PDF
            complet de la transaction : verdict, score IA, vecteurs utilisés, notes de l'analyste,
            horodatage et informations de l'utilisateur connecté.</div>
        </div>
    </div>

    <div class="guide-feat-row">
        <div class="guide-feat-icon">📁</div>
        <div class="guide-feat-body">
            <div class="guide-feat-title">Analyse en lot CSV</div>
            <div class="guide-feat-desc">Importez un fichier CSV avec plusieurs transactions pour les analyser toutes
            d'un coup. Un template CSV est téléchargeable dans l'onglet dédié pour connaître
            le format exact attendu (colonnes : montant, horodatage, V1 à V28).</div>
        </div>
    </div>

    <div class="guide-feat-row">
        <div class="guide-feat-icon">🗺️</div>
        <div class="guide-feat-body">
            <div class="guide-feat-title">Carte de risque géographique — Côte d'Ivoire</div>
            <div class="guide-feat-desc">Dans le Tableau de bord, une carte interactive de la Côte d'Ivoire
            représente les zones géographiques associées à un risque de fraude plus élevé,
            basée sur les données analysées.</div>
        </div>
    </div>

    <div class="guide-feat-row">
        <div class="guide-feat-icon">💰</div>
        <div class="guide-feat-body">
            <div class="guide-feat-title">Estimation des pertes évitées</div>
            <div class="guide-feat-desc">L'application calcule une estimation des pertes financières évitées
            grâce à la détection des transactions frauduleuses dans votre session, affichée en FCFA
            dans le Tableau de bord.</div>
        </div>
    </div>

    <div class="guide-feat-row">
        <div class="guide-feat-icon">🔐</div>
        <div class="guide-feat-body">
            <div class="guide-feat-title">Sécurité & Authentification</div>
            <div class="guide-feat-desc">L'accès à TrustLink est sécurisé par deux méthodes :
            <strong style="color:#fff;">Google OAuth 2.0</strong> (pour les utilisateurs normaux via leur compte Gmail)
            et un <strong style="color:#fff;">accès admin local</strong> avec mot de passe hashé PBKDF2-SHA256.
            Un système anti-brute-force bloque l'accès après 5 tentatives échouées (5 min de verrouillage).
            La session expire automatiquement après 30 minutes d'inactivité.</div>
        </div>
    </div>

    <div class="guide-feat-row">
        <div class="guide-feat-icon">⏱️</div>
        <div class="guide-feat-body">
            <div class="guide-feat-title">Horloge temps réel</div>
            <div class="guide-feat-desc">La barre latérale affiche l'heure en temps réel (HH:MM:SS),
            mise à jour à chaque interaction avec l'application.</div>
        </div>
    </div>

    <div class="guide-feat-row">
        <div class="guide-feat-icon">🎉</div>
        <div class="guide-feat-body">
            <div class="guide-feat-title">Confetti — Zéro fraude</div>
            <div class="guide-feat-desc">Dans l'analyse en lot, si vous analysez 10 transactions ou plus
            sans qu'aucune fraude ne soit détectée, l'application déclenche une animation de confetti
            pour célébrer la propreté du lot !</div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

    # ── Footer guide ──────────────────────────────────────────────────────────
    st.markdown("""
    <div style="text-align:center; color:#3a5070; font-size:11.5px; font-weight:700;
        margin-top:1.5rem; letter-spacing:0.5px; padding:1rem;
        border-top:1px solid #1e2d52;">
        🛡️ Hemerson TrustLink v5.0 &nbsp;•&nbsp; Auteur : Anoh Amon Francklin Hemerson
        &nbsp;•&nbsp; Superviseur : M. AKPOSSO DIDIER MARTIAL &nbsp;•&nbsp; © 2026 INSSEDS
    </div>
    """, unsafe_allow_html=True)

# ╔═════════════════════════════════════════════════════════════════════════════╗
# ║ ONGLET 5 - PANNEAU ADMIN SECRET                                             ║
# ╚═════════════════════════════════════════════════════════════════════════════╝
if _is_admin_panel and tab5 is not None:
    with tab5:
        st.markdown("""
        <style>
        .admin-header {
            background: linear-gradient(135deg, #1a0a2e, #2d1b69);
            border: 2px solid #7c3aed;
            border-radius: 16px;
            padding: 1.5rem 2rem;
            margin-bottom: 1.5rem;
            text-align: center;
        }
        .admin-stat {
            background: linear-gradient(135deg, #111b3d, #192551);
            border: 2px solid #4f7bff;
            border-radius: 12px;
            padding: 1.2rem;
            text-align: center;
        }
        .admin-table-wrap {
            background: #0d1530;
            border: 2px solid #2a3f5f;
            border-radius: 14px;
            padding: 1.2rem;
            margin-top: 1rem;
        }
        </style>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="admin-header">
            <div style="font-size:40px; margin-bottom:0.5rem;">🔐</div>
            <h2 style="color:#a78bfa; font-size:22px; font-weight:900;
                margin:0 0 0.3rem; text-transform:uppercase; letter-spacing:2px;">
                PANNEAU ADMINISTRATEUR
            </h2>
            <p style="color:#7c8db5; font-size:13px; margin:0; font-weight:600;">
                Accès réservé — Hemerson TrustLink v5.0
            </p>
        </div>
        """, unsafe_allow_html=True)

        # ── Charger les visiteurs
        _all_visitors = _visitors_load()
        _total        = len(_all_visitors)
        _google_users = sum(1 for v in _all_visitors if v.get("login_type") == "google")
        _admin_users  = sum(1 for v in _all_visitors if v.get("role") == "admin")
        _total_conn   = sum(v.get("nb_connexions", 1) for v in _all_visitors)

        # ── Stats rapides
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.markdown(f"""
            <div class="admin-stat">
                <div style="color:#a0aec0; font-size:11px; font-weight:700;
                    text-transform:uppercase; letter-spacing:1px;">Utilisateurs uniques</div>
                <div style="color:#ffffff; font-size:36px; font-weight:900;">{_total}</div>
            </div>""", unsafe_allow_html=True)
        with c2:
            st.markdown(f"""
            <div class="admin-stat">
                <div style="color:#a0aec0; font-size:11px; font-weight:700;
                    text-transform:uppercase; letter-spacing:1px;">Via Google</div>
                <div style="color:#4f7bff; font-size:36px; font-weight:900;">{_google_users}</div>
            </div>""", unsafe_allow_html=True)
        with c3:
            st.markdown(f"""
            <div class="admin-stat">
                <div style="color:#a0aec0; font-size:11px; font-weight:700;
                    text-transform:uppercase; letter-spacing:1px;">Connexions totales</div>
                <div style="color:#2ed573; font-size:36px; font-weight:900;">{_total_conn}</div>
            </div>""", unsafe_allow_html=True)
        with c4:
            st.markdown(f"""
            <div class="admin-stat">
                <div style="color:#a0aec0; font-size:11px; font-weight:700;
                    text-transform:uppercase; letter-spacing:1px;">Admins</div>
                <div style="color:#a78bfa; font-size:36px; font-weight:900;">{_admin_users}</div>
            </div>""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # ── Tableau des utilisateurs
        st.markdown("""
        <div style="color:#ffffff; font-size:16px; font-weight:900;
            text-transform:uppercase; letter-spacing:1px; margin-bottom:0.8rem;">
            📋 Liste des utilisateurs connectés
        </div>
        """, unsafe_allow_html=True)

        if _all_visitors:
            # Trier par dernière connexion (plus récente en premier)
            _all_visitors_sorted = sorted(
                _all_visitors,
                key=lambda v: v.get("derniere_connexion", ""),
                reverse=True
            )
            df_visitors = pd.DataFrame(_all_visitors_sorted)
            # Renommer les colonnes pour l'affichage
            _col_rename = {
                "email":              "📧 Email",
                "nom":                "👤 Nom",
                "role":               "🎭 Rôle",
                "login_type":         "🔑 Connexion",
                "premiere_connexion": "📅 1ère connexion",
                "derniere_connexion": "🕐 Dernière connexion",
                "nb_connexions":      "🔁 Nb connexions",
            }
            df_display = df_visitors.rename(columns=_col_rename)
            st.dataframe(df_display, use_container_width=True, hide_index=True)

            # Bouton export CSV
            st.markdown("<br>", unsafe_allow_html=True)
            _csv_visitors = df_display.to_csv(index=False).encode("utf-8")
            col_exp, col_del, _ = st.columns([2, 2, 3])
            with col_exp:
                st.download_button(
                    "📥 EXPORTER CSV",
                    _csv_visitors,
                    "trustlink_visiteurs.csv",
                    "text/csv",
                    use_container_width=True
                )
            with col_del:
                if st.button("🗑️ EFFACER LES LOGS", use_container_width=True):
                    _visitors_save([])
                    st.success("✅ Logs effacés.")
                    time.sleep(0.8)
                    st.rerun()
        else:
            st.info("Aucun visiteur enregistré pour le moment.")

        # ── Infos session admin courante
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("""
        <div style="color:#7c8db5; font-size:12px; font-weight:700;
            text-transform:uppercase; letter-spacing:1px; margin-bottom:0.5rem;">
            🖥️ Session admin courante
        </div>
        """, unsafe_allow_html=True)
        st.json({
            "email":      st.session_state.get("user_email", ""),
            "nom":        st.session_state.get("user_nom", ""),
            "role":       st.session_state.get("user_role", ""),
            "login_type": st.session_state.get("login_type", ""),
            "heure":      datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        })