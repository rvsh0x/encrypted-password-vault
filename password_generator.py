"""
Générateur de mots de passe sécurisés via le module secrets (CSPRNG).
"""

import secrets
import string
from typing import Optional


def generate_password(
    length: int = 20,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_special: bool = True,
    custom_special: Optional[str] = None,
) -> str:
    """
    Génère un mot de passe cryptographiquement sûr avec secrets.SystemRandom.

    :param length: Longueur du mot de passe
    :param use_uppercase: Inclure A-Z
    :param use_lowercase: Inclure a-z
    :param use_digits: Inclure 0-9
    :param use_special: Inclure caractères spéciaux (ou custom_special)
    :param custom_special: Ensemble de caractères spéciaux personnalisé
    :return: Mot de passe généré
    """
    if length < 4:
        length = 4
    pool: list[str] = []
    if use_lowercase:
        pool.extend(string.ascii_lowercase)
    if use_uppercase:
        pool.extend(string.ascii_uppercase)
    if use_digits:
        pool.extend(string.digits)
    if use_special:
        pool.extend(custom_special if custom_special else "!@#$%^&*()_+-=[]{}|;:,.<>?")
    if not pool:
        pool = list(string.ascii_letters + string.digits)
    return "".join(secrets.choice(pool) for _ in range(length))
