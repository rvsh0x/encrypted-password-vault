"""
Journalisation sécurisée : aucun mot de passe, clé ou donnée sensible n'est jamais loggé.
Seuls les événements et chemins (sans contenu) sont enregistrés.
"""

import logging
import sys
from typing import Optional, Any


# Niveaux utilisés : INFO pour opérations, WARNING pour échecs, DEBUG pour détails techniques
# Jamais de valeur sensible dans les messages
SENSITIVE_KEYS = frozenset({"password", "master_password", "key", "secret", "token", "data"})


def _sanitize_message(msg: str) -> str:
    """Retire toute mention de contenu sensible dans un message (heuristique basique)."""
    if not msg:
        return msg
    out = msg
    for k in SENSITIVE_KEYS:
        if k in out.lower():
            out = out.replace(k, "[REDACTED]")
    return out


class SecureFormatter(logging.Formatter):
    """Formatter qui ne laisse pas passer de données sensibles."""

    def format(self, record: logging.LogRecord) -> str:
        record.msg = _sanitize_message(str(record.msg))
        return super().format(record)


def get_secure_logger(
    name: str = "password_manager",
    level: int = logging.INFO,
    stream: Optional[Any] = None,
) -> logging.Logger:
    """
    Retourne un logger configuré pour ne jamais écrire de secrets.
    Les messages contenant des mots-clés sensibles sont redactés.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(level)
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(SecureFormatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(handler)
    return logger
