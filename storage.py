"""
Stockage du coffre : lecture/écriture du fichier vault chiffré.
Format versionné : { "version": 1, "salt": base64, "data": base64 }
"""

import os
import json
import base64
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import PasswordEntry, VAULT_FORMAT_VERSION, VaultMetadata


# Clé du format vault (versionné)
VAULT_VERSION_KEY = "version"
VAULT_SALT_KEY = "salt"
VAULT_DATA_KEY = "data"


def _entries_to_json(entries: List[PasswordEntry]) -> str:
    """Sérialise la liste d'entrées en JSON (à chiffrer)."""
    data = [e.to_dict() for e in entries]
    return json.dumps(data, ensure_ascii=False, indent=0)


def _json_to_entries(json_str: str) -> List[PasswordEntry]:
    """Désérialise le JSON en liste d'entrées."""
    data = json.loads(json_str)
    return [PasswordEntry.from_dict(item) for item in data]


def vault_file_path(vault_path: Optional[str] = None) -> Path:
    """Retourne le chemin du fichier vault (par défaut: ./vault.enc)."""
    if vault_path:
        return Path(vault_path)
    return Path.cwd() / "vault.enc"


def vault_exists(vault_path: Optional[str] = None) -> bool:
    """Indique si le fichier vault existe."""
    return vault_file_path(vault_path).exists()


def read_vault_file(vault_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Lit le fichier vault (format JSON non chiffré : version, salt, data).
    Ne déchiffre pas les données ; retourne le contenu brut pour crypto.
    """
    path = vault_file_path(vault_path)
    if not path.exists():
        raise FileNotFoundError(f"Vault non trouvé : {path}")
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    version = raw.get(VAULT_VERSION_KEY, 1)
    if version > VAULT_FORMAT_VERSION:
        raise ValueError(
            f"Format vault (version {version}) non supporté. "
            f"Version max : {VAULT_FORMAT_VERSION}"
        )
    return raw


def write_vault_file(
    salt_b64: str,
    encrypted_data_b64: str,
    vault_path: Optional[str] = None,
    version: int = VAULT_FORMAT_VERSION,
) -> None:
    """
    Écrit le fichier vault (version, salt, data chiffrée en base64).
    """
    path = vault_file_path(vault_path)
    payload = {
        VAULT_VERSION_KEY: version,
        VAULT_SALT_KEY: salt_b64,
        VAULT_DATA_KEY: encrypted_data_b64,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    # Écriture atomique : écriture dans un fichier temporaire puis rename
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=0)
        os.replace(tmp_path, path)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        raise


def decode_salt_from_vault(raw: Dict[str, Any]) -> bytes:
    """Extrait et décode le salt depuis le vault brut."""
    salt_b64 = raw.get(VAULT_SALT_KEY)
    if not salt_b64:
        raise ValueError("Vault invalide : salt manquant")
    return base64.b64decode(salt_b64.encode("ascii"))


def decode_encrypted_data_from_vault(raw: Dict[str, Any]) -> str:
    """Extrait la donnée chiffrée (chaîne base64) depuis le vault brut."""
    data = raw.get(VAULT_DATA_KEY)
    if not data:
        raise ValueError("Vault invalide : données manquantes")
    return data
