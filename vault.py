"""
Logique du coffre-fort : déverrouillage, ajout/suppression/listage d'entrées,
chiffrement/déchiffrement via crypto et storage.
"""

import base64
import uuid
from typing import List, Optional

from .crypto import (
    derive_key,
    generate_salt,
    encrypt_vault_data,
    decrypt_vault_data,
)
from .models import PasswordEntry, VAULT_FORMAT_VERSION
from .storage import (
    vault_exists,
    vault_file_path,
    read_vault_file,
    write_vault_file,
    decode_salt_from_vault,
    decode_encrypted_data_from_vault,
    _entries_to_json,
    _json_to_entries,
)


class VaultError(Exception):
    """Erreur liée au coffre (mot de passe incorrect, vault corrompu, etc.)."""
    pass


class Vault:
    """
    Coffre-fort en mémoire après déverrouillage.
    La clé dérivée et les entrées ne sont pas persistées en clair.
    """

    def __init__(self, vault_path: Optional[str] = None):
        self._vault_path = vault_path
        self._key: Optional[bytes] = None
        self._entries: List[PasswordEntry] = []
        self._locked = True

    @property
    def is_locked(self) -> bool:
        return self._locked

    @property
    def vault_path(self) -> Optional[str]:
        return self._vault_path

    def init(self, master_password: str) -> None:
        """
        Initialise un nouveau coffre : génère un salt, dérive la clé,
        crée un vault vide et l'enregistre.
        """
        # On considère qu'un fichier existant mais vide (cas des tests avec mkstemp)
        # peut être utilisé pour initialiser le coffre ; seul un fichier non vide
        # est traité comme un coffre déjà existant.
        path = vault_file_path(self._vault_path)
        if path.exists() and path.stat().st_size > 0:
            raise VaultError("Un coffre existe déjà à cet emplacement.")
        salt = generate_salt()
        key = derive_key(master_password, salt)
        self._key = key
        self._entries = []
        self._locked = False
        self._save(salt)

    def unlock(self, master_password: str) -> None:
        """
        Déverrouille le coffre : lit le vault, dérive la clé depuis le mot de passe,
        déchiffre les données. Lève VaultError si le mot de passe est incorrect
        ou si le vault est corrompu.
        """
        if not vault_exists(self._vault_path):
            raise VaultError("Aucun coffre trouvé. Utilisez 'init' pour en créer un.")
        raw = read_vault_file(self._vault_path)
        salt = decode_salt_from_vault(raw)
        encrypted_b64 = decode_encrypted_data_from_vault(raw)
        key = derive_key(master_password, salt)
        try:
            plaintext = decrypt_vault_data(encrypted_b64, key)
        except Exception as e:
            # Mauvaise clé ou données altérées
            raise VaultError("Mot de passe maître incorrect ou coffre corrompu.") from e
        self._key = key
        self._entries = _json_to_entries(plaintext)
        self._locked = False

    def lock(self) -> None:
        """Verrouille le coffre (efface clé et entrées de la mémoire)."""
        self._key = None
        self._entries = []
        self._locked = True

    def _save(self, salt: Optional[bytes] = None) -> None:
        """Persiste les entrées chiffrées. Utilise le salt existant si non fourni."""
        if self._locked or self._key is None:
            raise VaultError("Coffre verrouillé.")
        if salt is None:
            raw = read_vault_file(self._vault_path)
            current_salt = decode_salt_from_vault(raw)
        else:
            current_salt = salt
        plaintext = _entries_to_json(self._entries)
        encrypted_b64 = encrypt_vault_data(plaintext, self._key)
        salt_b64 = base64.b64encode(current_salt).decode("ascii")
        write_vault_file(salt_b64, encrypted_b64, self._vault_path, version=VAULT_FORMAT_VERSION)

    def save(self) -> None:
        """Sauvegarde le coffre (salt déjà dans le fichier)."""
        if self._locked or self._key is None:
            raise VaultError("Coffre verrouillé.")
        raw = read_vault_file(self._vault_path)
        salt = decode_salt_from_vault(raw)
        self._save(salt)

    def add_entry(
        self,
        site: str,
        username: str,
        password: str,
        notes: Optional[str] = None,
    ) -> PasswordEntry:
        """Ajoute une entrée et la persiste."""
        if self._locked:
            raise VaultError("Coffre verrouillé.")
        entry = PasswordEntry(
            site=site.strip(),
            username=username.strip(),
            password=password,
            notes=notes.strip() if notes else None,
            id=str(uuid.uuid4()),
        )
        self._entries.append(entry)
        self.save()
        return entry

    def list_entries(self) -> List[PasswordEntry]:
        """Retourne la liste des entrées (sans les mots de passe pour affichage liste)."""
        if self._locked:
            raise VaultError("Coffre verrouillé.")
        return list(self._entries)

    def get_entry(self, entry_id: str) -> Optional[PasswordEntry]:
        """Retourne une entrée par son id."""
        if self._locked:
            raise VaultError("Coffre verrouillé.")
        for e in self._entries:
            if e.id == entry_id:
                return e
        return None

    def get_entry_by_index(self, index: int) -> Optional[PasswordEntry]:
        """Retourne une entrée par index (1-based pour l'utilisateur)."""
        if self._locked:
            raise VaultError("Coffre verrouillé.")
        if 1 <= index <= len(self._entries):
            return self._entries[index - 1]
        return None

    def delete_entry(self, entry_id: str) -> bool:
        """Supprime une entrée par id. Retourne True si supprimée."""
        if self._locked:
            raise VaultError("Coffre verrouillé.")
        for i, e in enumerate(self._entries):
            if e.id == entry_id:
                del self._entries[i]
                self.save()
                return True
        return False

    def delete_entry_by_index(self, index: int) -> bool:
        """Supprime une entrée par index (1-based)."""
        if self._locked:
            raise VaultError("Coffre verrouillé.")
        if 1 <= index <= len(self._entries):
            entry = self._entries[index - 1]
            return self.delete_entry(entry.id or "")
        return False
