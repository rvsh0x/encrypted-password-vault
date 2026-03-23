"""
Modèles de données pour le gestionnaire de mots de passe.
Aucune donnée sensible n'est loggée.
"""

from dataclasses import dataclass, asdict
from typing import Optional
import json


# Version du format du vault (pour évolution future)
VAULT_FORMAT_VERSION = 1


@dataclass
class PasswordEntry:
    """Représente une entrée du coffre (identifiants)."""

    site: str
    username: str
    password: str
    notes: Optional[str] = None
    id: Optional[str] = None

    def to_dict(self) -> dict:
        """Sérialisation pour stockage (sans exposer en log)."""
        d = asdict(self)
        # Retirer les clés None pour compatibilité
        return {k: v for k, v in d.items() if v is not None}

    @classmethod
    def from_dict(cls, data: dict) -> "PasswordEntry":
        """Désérialisation depuis le stockage."""
        return cls(
            site=data.get("site", ""),
            username=data.get("username", ""),
            password=data.get("password", ""),
            notes=data.get("notes"),
            id=data.get("id"),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_json(cls, s: str) -> "PasswordEntry":
        return cls.from_dict(json.loads(s))


@dataclass
class VaultMetadata:
    """Métadonnées du vault (version, salt stocké côté storage)."""

    version: int = VAULT_FORMAT_VERSION

    def to_dict(self) -> dict:
        return {"version": self.version}

    @classmethod
    def from_dict(cls, data: dict) -> "VaultMetadata":
        return cls(version=data.get("version", VAULT_FORMAT_VERSION))
