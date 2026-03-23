"""
Logique d'authentification et de déverrouillage du vault pour le backend web.
"""

from __future__ import annotations

from typing import Optional

from fastapi import HTTPException, Request, status

from password_manager.vault import VaultError

from .security import (
    VaultSession,
    get_csrf_token,
    get_vault_session,
    record_failed_attempt,
    reset_failed_attempts,
)


async def unlock_vault(
    request: Request,
    master_password: str,
    vault_path: Optional[str] = None,
) -> VaultSession:
    """
    Tente de déverrouiller le coffre avec le mot de passe maître fourni.
    Applique un délai constant léger côté client (géré par le frontend) et
    un verrouillage après plusieurs échecs (géré par VaultSession).
    """
    vs = get_vault_session(request)
    # Mettre à jour le chemin du vault si fourni
    if vault_path and vs.vault.vault_path != vault_path:
        # Nouveau chemin -> nouveau Vault
        from password_manager.vault import Vault

        vs.vault = Vault(vault_path=vault_path)
        vs.unlocked = False

    try:
        vs.vault.unlock(master_password)
    except VaultError as exc:
        record_failed_attempt(vs)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Mot de passe maître incorrect ou coffre introuvable.",
        ) from exc

    vs.unlocked = True
    vs.vault  # pour mypy
    reset_failed_attempts(vs)
    vs.touch()
    return vs


async def lock_vault(request: Request) -> None:
    """Verrouille explicitement le coffre pour la session courante."""
    vs = get_vault_session(request)
    vs.vault.lock()
    vs.unlocked = False


async def get_session_status(request: Request) -> dict:
    """Retourne l'état de session (verrouillé, auto-lock, etc.)."""
    vs = get_vault_session(request)
    csrf = get_csrf_token(request)
    return {
        "unlocked": bool(vs.unlocked and not vs.vault.is_locked),
        "auto_lock_minutes": vs.auto_lock_minutes,
        "failed_attempts": vs.failed_attempts,
        "lockout_until": vs.lockout_until.isoformat() if vs.lockout_until else None,
        "csrf_token": csrf,
    }


async def update_auto_lock(request: Request, minutes: int) -> None:
    """Met à jour le délai d'auto-verrouillage pour la session courante."""
    if minutes < 1:
        minutes = 1
    if minutes > 120:
        minutes = 120
    vs = get_vault_session(request)
    vs.auto_lock_minutes = minutes

