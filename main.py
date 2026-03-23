#!/usr/bin/env python3
"""
Point d'entrée CLI du gestionnaire de mots de passe.
Utilise argparse, getpass, logs sécurisés, verrouillage après N tentatives,
protection timing (délai constant en cas d'échec).
"""

import argparse
import getpass
import sys
import time
from typing import Optional

from .vault import Vault, VaultError
from .storage import vault_exists, vault_file_path
from .password_generator import generate_password
from .secure_logger import get_secure_logger

# Verrouillage après N échecs (protection bruteforce)
MAX_UNLOCK_ATTEMPTS = 5
LOCKOUT_SECONDS = 60
# Délai constant en cas d'échec d'auth (réduit fuite par timing)
AUTH_FAILURE_DELAY_SECONDS = 0.5

logger = get_secure_logger("password_manager")

# État global pour verrouillage après N échecs (évite bruteforce)
_failed_attempts = 0
_lockout_until = 0.0


def _copy_to_clipboard(text: str) -> bool:
    """Copie le texte dans le presse-papier si disponible."""
    try:
        import subprocess
        proc = subprocess.run(
            ["pbcopy"] if sys.platform == "darwin" else ["xclip", "-selection", "clipboard"] if sys.platform.startswith("linux") else ["clip"],
            input=text.encode("utf-8"),
            check=False,
            capture_output=True,
        )
        return proc.returncode == 0
    except (FileNotFoundError, OSError):
        return False


def _get_master_password(prompt: str = "Mot de passe maître : ") -> str:
    return getpass.getpass(prompt=prompt)


def _ensure_unlocked(vault: Vault, vault_path: Optional[str]) -> bool:
    """Déverrouille le coffre si nécessaire. Retourne True si déverrouillé."""
    global _failed_attempts, _lockout_until
    if not vault.is_locked:
        return True
    if not vault_exists(vault_path):
        logger.error("Aucun coffre trouvé. Utilisez 'init' pour en créer un.")
        return False
    now = time.time()
    if now < _lockout_until:
        wait = int(_lockout_until - now)
        logger.error("Trop de tentatives. Réessayez dans %d secondes.", wait)
        return False
    password = _get_master_password()
    try:
        vault.unlock(password)
        _failed_attempts = 0
        logger.info("Coffre déverrouillé.")
        return True
    except VaultError as e:
        _failed_attempts += 1
        logger.warning("Échec déverrouillage : %s", str(e))
        time.sleep(AUTH_FAILURE_DELAY_SECONDS)
        if _failed_attempts >= MAX_UNLOCK_ATTEMPTS:
            _lockout_until = time.time() + LOCKOUT_SECONDS
            logger.error("Verrouillage pendant %d secondes.", LOCKOUT_SECONDS)
        return False


def cmd_init(args: argparse.Namespace, vault: Vault) -> int:
    if vault_exists(args.vault):
        logger.error("Un coffre existe déjà. Supprimez-le ou utilisez un autre chemin.")
        return 1
    password = _get_master_password("Nouveau mot de passe maître : ")
    confirm = _get_master_password("Confirmez le mot de passe maître : ")
    if password != confirm:
        logger.error("Les mots de passe ne correspondent pas.")
        return 1
    try:
        vault.init(password)
        logger.info("Coffre créé : %s", vault_file_path(args.vault))
        return 0
    except VaultError as e:
        logger.error("%s", e)
        return 1


def cmd_unlock(args: argparse.Namespace, vault: Vault) -> int:
    attempts = 0
    while attempts < MAX_UNLOCK_ATTEMPTS:
        if _ensure_unlocked(vault, args.vault):
            return 0
        attempts += 1
        if attempts < MAX_UNLOCK_ATTEMPTS:
            logger.warning("Tentative %d/%d.", attempts, MAX_UNLOCK_ATTEMPTS)
    logger.error("Trop de tentatives. Verrouillage pendant %d secondes.", LOCKOUT_SECONDS)
    time.sleep(LOCKOUT_SECONDS)
    return 1


def cmd_add(args: argparse.Namespace, vault: Vault) -> int:
    if not _ensure_unlocked(vault, args.vault):
        return 1
    site = args.site or input("Site / application : ").strip()
    username = args.username or input("Identifiant : ").strip()
    if args.password:
        password = args.password
    else:
        password = getpass.getpass("Mot de passe (vide = générer) : ")
        if not password and args.generate:
            password = generate_password(length=args.length or 20, use_special=not args.no_special)
            print("Généré :", password)
        elif not password:
            gen = input("Générer un mot de passe ? (o/N) : ").strip().lower()
            if gen == "o":
                password = generate_password(length=args.length or 20)
                print("Généré :", password)
    if not password:
        logger.error("Mot de passe requis.")
        return 1
    notes = args.notes
    try:
        vault.add_entry(site=site, username=username, password=password, notes=notes)
        logger.info("Entrée ajoutée pour %s.", site)
        return 0
    except VaultError as e:
        logger.error("%s", e)
        return 1


def cmd_list(args: argparse.Namespace, vault: Vault) -> int:
    if not _ensure_unlocked(vault, args.vault):
        return 1
    entries = vault.list_entries()
    if not entries:
        print("Aucune entrée.")
        return 0
    for i, e in enumerate(entries, 1):
        mask = "***" if e.password else "-"
        print(f"  {i}. {e.site} | {e.username} | {mask}")
    return 0


def cmd_show(args: argparse.Namespace, vault: Vault) -> int:
    if not _ensure_unlocked(vault, args.vault):
        return 1
    if args.index:
        entry = vault.get_entry_by_index(args.index)
    elif args.id:
        entry = vault.get_entry(args.id)
    else:
        logger.error("Indiquez --index ou --id.")
        return 1
    if not entry:
        logger.error("Entrée non trouvée.")
        return 1
    print("Site    :", entry.site)
    print("Utilisateur :", entry.username)
    print("Mot de passe :", entry.password)
    if entry.notes:
        print("Notes   :", entry.notes)
    if args.copy:
        if _copy_to_clipboard(entry.password):
            logger.info("Mot de passe copié dans le presse-papier.")
        else:
            print("(Copie presse-papier non disponible)")
    return 0


def cmd_delete(args: argparse.Namespace, vault: Vault) -> int:
    if not _ensure_unlocked(vault, args.vault):
        return 1
    if args.index:
        ok = vault.delete_entry_by_index(args.index)
    elif args.id:
        ok = vault.delete_entry(args.id)
    else:
        logger.error("Indiquez --index ou --id.")
        return 1
    if not ok:
        logger.error("Entrée non trouvée.")
        return 1
    logger.info("Entrée supprimée.")
    return 0


def cmd_generate(args: argparse.Namespace, _vault: Vault) -> int:
    pwd = generate_password(
        length=args.length or 20,
        use_uppercase=not args.no_upper,
        use_lowercase=not args.no_lower,
        use_digits=not args.no_digits,
        use_special=not args.no_special,
    )
    print(pwd)
    if args.copy:
        if _copy_to_clipboard(pwd):
            logger.info("Copié dans le presse-papier.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Gestionnaire de mots de passe chiffré (AES-256-GCM, Argon2id)")
    parser.add_argument("--vault", "-v", default=None, help="Chemin du fichier vault (défaut: ./vault.enc)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Créer un nouveau coffre")
    sub.add_parser("unlock", help="Déverrouiller le coffre")
    sub.add_parser("list", help="Lister les entrées")

    p_add = sub.add_parser("add", help="Ajouter une entrée")
    p_add.add_argument("--site", "-s", help="Site / application")
    p_add.add_argument("--username", "-u", help="Identifiant")
    p_add.add_argument("--password", "-p", help="Mot de passe (éviter en CLI)")
    p_add.add_argument("--notes", "-n", help="Notes")
    p_add.add_argument("--generate", "-g", action="store_true", help="Générer le mot de passe")
    p_add.add_argument("--length", "-l", type=int, help="Longueur si génération")
    p_add.add_argument("--no-special", action="store_true", help="Sans caractères spéciaux si génération")

    p_show = sub.add_parser("show", help="Afficher une entrée")
    p_show.add_argument("--index", "-i", type=int, help="Numéro d'entrée (1-based)")
    p_show.add_argument("--id", help="ID d'entrée")
    p_show.add_argument("--copy", "-c", action="store_true", help="Copier le mot de passe dans le presse-papier")

    p_del = sub.add_parser("delete", help="Supprimer une entrée")
    p_del.add_argument("--index", "-i", type=int, help="Numéro d'entrée")
    p_del.add_argument("--id", help="ID d'entrée")

    p_gen = sub.add_parser("generate", help="Générer un mot de passe (sans l'enregistrer)")
    p_gen.add_argument("--length", "-l", type=int, default=20, help="Longueur")
    p_gen.add_argument("--no-upper", action="store_true", help="Sans majuscules")
    p_gen.add_argument("--no-lower", action="store_true", help="Sans minuscules")
    p_gen.add_argument("--no-digits", action="store_true", help="Sans chiffres")
    p_gen.add_argument("--no-special", action="store_true", help="Sans caractères spéciaux")
    p_gen.add_argument("--copy", "-c", action="store_true", help="Copier dans le presse-papier")

    args = parser.parse_args()
    vault = Vault(vault_path=args.vault)

    handlers = {
        "init": cmd_init,
        "unlock": cmd_unlock,
        "add": cmd_add,
        "list": cmd_list,
        "show": cmd_show,
        "delete": cmd_delete,
        "generate": cmd_generate,
    }
    handler = handlers[args.command]
    return handler(args, vault)


if __name__ == "__main__":
    sys.exit(main())
