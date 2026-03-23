# Gestionnaire de mots de passe sécurisé (CLI + Web)

Application de gestion de mots de passe qui stocke les identifiants (site, utilisateur, mot de passe, notes) dans un **coffre-fort chiffré local** (fichier vault), utilisable :

- en **ligne de commande (CLI)** ;
- via une **interface web locale** moderne (FastAPI + HTML/CSS/JS), accessible uniquement sur `localhost`.

## Exigences de sécurité

- **Chiffrement** : AES-256 en mode **GCM** (authentifié : confidentialité + intégrité, pas de HMAC séparé).
- **Dérivation de clé** : **Argon2id** (prioritaire), ou PBKDF2-HMAC-SHA256 si `argon2-cffi` absent.
- **Salt** : 32 octets aléatoires (générés avec `secrets`), un par coffre.
- **IV/Nonce** : 12 octets aléatoires par opération de chiffrement (GCM).
- **Protection brute-force** : verrouillage après 5 tentatives de déverrouillage (60 s), côté CLI et côté web.
- **Timing** : délai constant après échec d’authentification pour limiter les fuites par temps.
- **Logs** : aucun mot de passe ni donnée sensible n’est jamais loggé.
- **Portée locale uniquement** : l’app web écoute sur `127.0.0.1` et refuse tout accès externe.

Les mots de passe ne sont **jamais** stockés en clair.

---

## Installation

À la racine du projet (répertoire contenant `password_manager/`) :

```bash
# Installation complète (CLI + web)
python3 -m pip install -r password_manager/requirements.txt
```

Python 3.11+ recommandé.

---

## Utilisation CLI (terminal)

Depuis la racine du projet (parent de `password_manager`) :

```bash
# Vault par défaut : ./vault.enc
python -m password_manager init
python -m password_manager unlock
python -m password_manager add
python -m password_manager list
python -m password_manager show --index 1
python -m password_manager delete --index 1
python -m password_manager generate --length 24 --copy
```

Avec un fichier vault personnalisé :

```bash
python -m password_manager --vault /chemin/vers/mon_vault.enc init
python -m password_manager --vault /chemin/vers/mon_vault.enc list
```

### Commandes CLI (argparse)

| Commande     | Description |
|-------------|-------------|
| `init`     | Crée un nouveau coffre (mot de passe maître demandé 2 fois). |
| `unlock`   | Déverrouille le coffre (jusqu’à 5 tentatives, puis verrouillage 60 s). |
| `add`      | Ajoute une entrée (site, username, mot de passe, notes). Options : `--site`, `--username`, `--password`, `--notes`, `--generate`, `--length`, `--no-special`. |
| `list`     | Liste les entrées (sans afficher les mots de passe). |
| `show`     | Affiche une entrée. `--index N` ou `--id <uuid>`, option `--copy` pour copier le mot de passe. |
| `delete`   | Supprime une entrée. `--index N` ou `--id <uuid>`. |
| `generate` | Génère un mot de passe (sans l’enregistrer). Options : `--length`, `--no-upper`, `--no-lower`, `--no-digits`, `--no-special`, `--copy`. |

Options globales : `--vault` / `-v` : chemin du fichier vault (défaut : `./vault.enc`).

---

## Interface web locale

L’interface web repose sur **FastAPI + Uvicorn** côté backend et des pages HTML/CSS/JS côté frontend.  
Tout reste sur ta machine : aucun appel sortant, aucune dépendance à un service externe.

### Lancement

Depuis la racine du projet :

```bash
python main_web.py
```

Puis dans ton navigateur :

```text
http://localhost:8000
```

### Parcours

- **Page d’accueil (`/`)** :  
  - Saisie du **mot de passe maître** (aucun mot de passe par défaut, c’est celui que tu as choisi lors du `init`).  
  - Chemin du fichier vault (`./vault.enc` par défaut, champ optionnel).  
  - En cas d’erreur (mauvais mot de passe, vault absent), un message clair s’affiche.

- **Dashboard (`/dashboard`)** :  
  - Liste de toutes les entrées (site, username, indicateur de présence d’un mot de passe).  
  - Recherche instantanée (filtrage côté client).  
  - Tri par site / username.

- **Ajouter une entrée (`/add`)** :  
  - Formulaire : site, username, password, notes.  
  - Générateur intégré (longueur configurable, option caractères spéciaux).  
  - Indicateur de force du mot de passe (longueur, diversité de caractères).

- **Détails d’une entrée (`/entry/{id}`)** :  
  - Affiche l’entrée complète.  
  - Boutons “Copier identifiant” / “Copier mot de passe” (via presse-papier local).  
  - Afficher/masquer le mot de passe.  
  - Modifier / enregistrer.  
  - Supprimer (avec confirmation).

- **Paramètres (`/settings`)** :  
  - Réglage de l’**auto-verrouillage** après X minutes d’inactivité (1–120 minutes).  
  - Informations sur la sécurité (chiffrement, dérivation, portée locale).

La navigation se fait via une **sidebar sombre** inspirée de Bitwarden / Proton Pass :  
Dashboard, Ajouter, Générateur (ancre sur la page d’ajout), Paramètres, Verrouiller.

---

## Architecture

```text
password_manager/
├── main.py               # CLI (argparse), verrouillage, délai anti-timing
├── main_web.py           # Création app FastAPI (backend + routes HTML)
├── backend/
│   ├── api.py            # Routes FastAPI (pages HTML + API REST locale)
│   ├── auth.py           # Déverrouillage, lock, état de session
│   ├── vault_service.py  # Adaptateur entre API et Vault (list/add/update/delete)
│   └── security.py       # SessionMiddleware, CSRF, auto-lock, brute-force
├── frontend/             # Templates HTML (servis via Jinja2)
│   ├── index.html        # Page de déverrouillage
│   ├── dashboard.html    # Dashboard avec recherche/tri
│   ├── add_entry.html    # Formulaire d’ajout + générateur + force
│   ├── view_entry.html   # Détails, copie, modification, suppression
│   └── settings.html     # Paramètres (auto-lock, infos sécurité)
├── static/
│   ├── css/styles.css    # Thème sombre type Tailwind (utility-like)
│   └── js/app.js         # Logique frontend (API, toasts, copie, force, auto-lock)
├── vault.py              # Logique coffre (init, unlock, add, get, delete)
├── crypto.py             # Argon2id/PBKDF2, AES-256-GCM, salt/nonce
├── storage.py            # Lecture/écriture fichier vault (format versionné)
├── models.py             # PasswordEntry, version du format
├── password_generator.py # Génération de mots de passe via secrets
├── secure_logger.py      # Logs sécurisés (aucune donnée sensible)
├── requirements.txt      # Dépendances (CLI + web)
└── tests/                # Tests pytest (crypto, vault, storage, générateur)
```

---

## Format du fichier vault (versionné)

Structure JSON sur disque (données chiffrées en base64) :

```json
{
  "version": 1,
  "salt": "<base64>",
  "data": "<base64: nonce + ciphertext GCM>"
}
```

- **version** : permet d’évoluer le format plus tard.  
- **salt** : utilisé pour la dérivation de clé (Argon2id/PBKDF2).  
- **data** : payload chiffré (nonce 12 octets + ciphertext+tag GCM), encodé en base64.

Le contenu déchiffré de `data` est un JSON : liste d’objets `PasswordEntry` (site, username, password, notes, id).

---

## Parties cryptographiques (résumé)

1. **Dérivation de clé (Argon2id / PBKDF2)**  
   Le mot de passe maître + salt sont transmis à Argon2id (time_cost, memory_cost, parallelism).  
   La sortie est une clé de 32 octets. Si `argon2-cffi` n’est pas disponible, on bascule sur PBKDF2-HMAC-SHA256 (600k itérations).

2. **Chiffrement (AES-256-GCM)**  
   Pour chaque sauvegarde du vault, un nonce de 12 octets est tiré aléatoirement.  
   AES-GCM chiffre le JSON (entrées) et produit un tag d’authentification.  
   Toute modification ou mauvaise clé est détectée au déchiffrement (exception levée).

3. **Intégrité**  
   GCM fournit l’intégrité (pas besoin de HMAC séparé).  
   Le fichier sur disque est donc à la fois **confidentiel** et **authentifié**.

4. **Comparaison en temps constant**  
   Les comparaisons sensibles (ex. hashes) utilisent `hmac.compare_digest` pour éviter les fuites par temps (timing attacks).

5. **Timing après échec**  
   Après un échec de déverrouillage, un délai fixe est appliqué dans la CLI.  
   Côté web, le backend applique un verrouillage après plusieurs échecs, et le frontend ne révèle que des messages d’erreur génériques.

---

## Tests

À la racine du projet :

```bash
PYTHONPATH=. python3 -m pytest password_manager/tests -v
```

Les tests couvrent : crypto (dérivation, chiffrement/déchiffrement, constant-time), modèles, storage, vault (init, unlock, add, list, delete), générateur de mots de passe.

Les 32 tests sont prévus pour passer (`32 passed`), ce qui valide le moteur cryptographique et la persistance du coffre.

---

## Bonus implémentés

- Verrouillage après 5 tentatives (60 s).  
- Copie du mot de passe dans le presse-papier (`--copy` en CLI, boutons “Copier” en web).  
- Tests unitaires pytest.  
- README détaillant la sécurité.  
- Logs sécurisés (aucune donnée sensible n’apparaît).  
- CLI avec argparse.  
- Format vault versionné (`"version": 1`).  
- Protection anti-timing (délai constant après échec, comparaison en temps constant).  
- Interface web sombre et moderne inspirée de Bitwarden / 1Password / Proton Pass.  
- Sessions locales avec CSRF et auto-verrouillage après X minutes d’inactivité.

