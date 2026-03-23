"""
Service d'accès au coffre pour l'API web.
Encapsule les opérations sur le Vault existant.
"""

from __future__ import annotations

from typing import List, Optional

from password_manager.models import PasswordEntry

from .security import VaultSession


def list_entries(vs: VaultSession) -> List[dict]:
    """Retourne une vue allégée des entrées (sans mot de passe)."""
    entries = vs.vault.list_entries()
    result: List[dict] = []
    for e in entries:
        result.append(
            {
                "id": e.id,
                "site": e.site,
                "username": e.username,
                # Pas de mot de passe en listing
                "has_password": bool(e.password),
            }
        )
    return result


def get_entry(vs: VaultSession, entry_id: str) -> Optional[PasswordEntry]:
    """Récupère une entrée complète (incluant le mot de passe)."""
    return vs.vault.get_entry(entry_id)


def add_entry(
    vs: VaultSession,
    site: str,
    username: str,
    password: str,
    notes: Optional[str] = None,
) -> PasswordEntry:
    """Ajoute une entrée au coffre."""
    return vs.vault.add_entry(site=site, username=username, password=password, notes=notes)


def update_entry(
    vs: VaultSession,
    entry_id: str,
    site: str,
    username: str,
    password: str,
    notes: Optional[str] = None,
) -> Optional[PasswordEntry]:
    """Met à jour une entrée existante."""
    entry = vs.vault.get_entry(entry_id)
    if not entry:
        return None
    entry.site = site
    entry.username = username
    entry.password = password
    entry.notes = notes
    vs.vault.save()
    return entry


def delete_entry(vs: VaultSession, entry_id: str) -> bool:
    """Supprime une entrée par id."""
    return vs.vault.delete_entry(entry_id)

