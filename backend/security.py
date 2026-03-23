"""
Sécurité backend : sessions locales, CSRF, auto-lock, verrouillage après
plusieurs mots de passe maître incorrects.

Important : tout reste local (FastAPI bind sur 127.0.0.1).
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from fastapi import Depends, HTTPException, Request, status
from starlette.middleware.sessions import SessionMiddleware

from password_manager.vault import Vault, VaultError


SESSION_VAULT_KEY = "session_id"
SESSION_CSRF_KEY = "csrf_token"

# Paramètres de sécurité
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 60
DEFAULT_AUTO_LOCK_MINUTES = 10


@dataclass
class VaultSession:
    """Contexte de session pour un utilisateur (local)."""

    vault: Vault
    unlocked: bool = False
    last_activity: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    failed_attempts: int = 0
    lockout_until: Optional[datetime] = None
    auto_lock_minutes: int = DEFAULT_AUTO_LOCK_MINUTES

    def touch(self) -> None:
        self.last_activity = datetime.now(timezone.utc)

    def is_locked_by_time(self) -> bool:
        if not self.unlocked:
            return True
        now = datetime.now(timezone.utc)
        return now - self.last_activity > timedelta(minutes=self.auto_lock_minutes)


class SessionStore:
    """
    Stockage en mémoire des sessions de vault.
    Uniquement en local, une seule instance de process.
    """

    def __init__(self) -> None:
        self._sessions: Dict[str, VaultSession] = {}

    def get_or_create(self, session_id: str, vault_path: Optional[str]) -> VaultSession:
        if session_id not in self._sessions:
            self._sessions[session_id] = VaultSession(vault=Vault(vault_path=vault_path))
        return self._sessions[session_id]

    def get(self, session_id: str) -> Optional[VaultSession]:
        return self._sessions.get(session_id)

    def clear(self, session_id: str) -> None:
        if session_id in self._sessions:
            del self._sessions[session_id]


session_store = SessionStore()


def add_session_middleware(app, secret_key: str) -> None:
    """Ajoute le SessionMiddleware à l'application FastAPI."""
    app.add_middleware(
        SessionMiddleware,
        secret_key=secret_key,
        https_only=False,
        max_age=None,
        same_site="lax",
        session_cookie="pm_session",
    )


def ensure_session_id(request: Request) -> str:
    """
    Retourne un identifiant de session stocké dans cookie signé.
    Créé si inexistant.
    """
    session = request.session
    sid = session.get(SESSION_VAULT_KEY)
    if not sid:
        sid = secrets.token_urlsafe(32)
        session[SESSION_VAULT_KEY] = sid
    return sid


def get_vault_session(request: Request) -> VaultSession:
    """Récupère (ou crée) la session de vault associée au cookie."""
    sid = ensure_session_id(request)
    vault_path: Optional[str] = None
    vs = session_store.get_or_create(sid, vault_path=vault_path)

    # Gestion auto-lock
    if vs.unlocked and vs.is_locked_by_time():
        vs.vault.lock()
        vs.unlocked = False

    # Gestion lockout
    if vs.lockout_until and datetime.now(timezone.utc) < vs.lockout_until:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Trop de tentatives. Réessayez plus tard.",
        )
    return vs


def get_csrf_token(request: Request) -> str:
    """Crée/récupère un token CSRF stocké en session."""
    token = request.session.get(SESSION_CSRF_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        request.session[SESSION_CSRF_KEY] = token
    return token


async def csrf_protect(request: Request) -> None:
    """
    Vérifie le token CSRF pour les méthodes non sûres.
    Utilise l'en-tête X-CSRF-Token et le token stocké en session.
    """
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    session_token = request.session.get(SESSION_CSRF_KEY)
    header_token = request.headers.get("X-CSRF-Token")
    if not session_token or not header_token or not secrets.compare_digest(
        session_token, header_token
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token invalide"
        )


def require_unlocked_vault(
    request: Request, vs: VaultSession = Depends(get_vault_session)
) -> VaultSession:
    """
    Dépendance FastAPI : s'assure que le coffre est déverrouillé.
    """
    if not vs.unlocked or vs.vault.is_locked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Coffre verrouillé",
        )
    vs.touch()
    return vs


def record_failed_attempt(vs: VaultSession) -> None:
    """Incrémente le compteur d'échecs et applique le lockout si besoin."""
    vs.failed_attempts += 1
    if vs.failed_attempts >= MAX_FAILED_ATTEMPTS:
        vs.lockout_until = datetime.now(timezone.utc) + timedelta(
            seconds=LOCKOUT_SECONDS
        )


def reset_failed_attempts(vs: VaultSession) -> None:
    vs.failed_attempts = 0
    vs.lockout_until = None

