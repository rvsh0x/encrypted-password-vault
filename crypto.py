"""
Module cryptographique : dérivation de clé (Argon2id), chiffrement AES-256-GCM.
- Argon2id : résistant au GPU/ASIC, protection brute-force.
- AES-256-GCM : chiffrement authentifié (intégrité + confidentialité).
- Comparaison en temps constant pour éviter les timing attacks.
"""

import base64
import hmac
import secrets
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False
    hash_secret_raw = None
    Argon2Type = None

# Constantes crypto
SALT_LENGTH = 32
NONCE_LENGTH = 12  # 96 bits recommandé pour GCM
KEY_LENGTH = 32  # 256 bits pour AES-256
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MiB
ARGON2_PARALLELISM = 4
PBKDF2_ITERATIONS = 600_000  # fallback si Argon2 absent


def _constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Comparaison en temps constant pour éviter les timing attacks
    (ex: fuite d'info sur la longueur du mot de passe ou du hash).
    """
    return hmac.compare_digest(a, b)


def derive_key_argon2(password: str, salt: bytes) -> bytes:
    """
    Dérive une clé 256 bits depuis le mot de passe maître avec Argon2id.
    Argon2id est résistant aux attaques par canal auxiliaire et au bruteforce GPU.
    """
    if not ARGON2_AVAILABLE or hash_secret_raw is None or Argon2Type is None:
        raise RuntimeError("argon2-cffi est requis pour la dérivation de clé.")
    # Argon2id (Type.ID) : dérivation de clé résistante GPU/ASIC et side-channel.
    return hash_secret_raw(
        password.encode("utf-8"),
        salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_LENGTH,
        type=Argon2Type.ID,
    )


def derive_key_pbkdf2(password: str, salt: bytes) -> bytes:
    """
    Fallback : dérivation de clé avec PBKDF2-HMAC-SHA256.
    Moins résistant au bruteforce que Argon2 mais standard.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def derive_key(password: str, salt: bytes, use_argon2: bool = True) -> bytes:
    """
    Dérive la clé de chiffrement depuis le mot de passe maître.
    Préfère Argon2id si disponible, sinon PBKDF2-HMAC-SHA256.
    """
    if use_argon2 and ARGON2_AVAILABLE:
        return derive_key_argon2(password, salt)
    return derive_key_pbkdf2(password, salt)


def generate_salt() -> bytes:
    """Génère un salt aléatoire cryptographiquement sûr (32 octets)."""
    return secrets.token_bytes(SALT_LENGTH)


def encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    """
    Chiffrement AES-256-GCM.
    Retourne (nonce || ciphertext || tag) concaténés, et on pourrait séparer;
    ici on laisse GCM gérer le tag (authentification).
    GCM fournit à la fois confidentialité et intégrité (pas besoin de HMAC séparé).
    """
    nonce = secrets.token_bytes(NONCE_LENGTH)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    # ciphertext contient déjà le tag à la fin (16 octets)
    return nonce, ciphertext


def decrypt(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """
    Déchiffrement AES-256-GCM.
    Vérifie automatiquement le tag d'authentification (intégrité).
    Lève une exception si le tag est invalide (données modifiées ou mauvaise clé).
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def encrypt_vault_data(plaintext_json: str, key: bytes) -> str:
    """
    Chiffre le contenu JSON du vault et retourne une chaîne base64
    encodant : nonce (12) + ciphertext+tag.
    """
    nonce, ciphertext = encrypt(plaintext_json.encode("utf-8"), key)
    payload = nonce + ciphertext
    return base64.b64encode(payload).decode("ascii")


def decrypt_vault_data(encoded: str, key: bytes) -> str:
    """
    Déchiffre la charge base64 (nonce + ciphertext+tag) et retourne le JSON en clair.
    """
    payload = base64.b64decode(encoded.encode("ascii"))
    nonce = payload[:NONCE_LENGTH]
    ciphertext = payload[NONCE_LENGTH:]
    return decrypt(nonce, ciphertext, key).decode("utf-8")


def verify_password_constant_time(provided_hash: bytes, expected_hash: bytes) -> bool:
    """Vérification en temps constant (évite timing attacks)."""
    return _constant_time_compare(provided_hash, expected_hash)
