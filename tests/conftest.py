"""Fixtures pytest : vault temporaire, mot de passe de test."""

import tempfile
import os
import pytest

from password_manager.vault import Vault


@pytest.fixture
def temp_vault_path():
    """Chemin vers un fichier vault temporaire (supprimé après le test)."""
    fd, path = tempfile.mkstemp(suffix=".enc")
    os.close(fd)
    try:
        yield path
    finally:
        if os.path.exists(path):
            os.unlink(path)


@pytest.fixture
def master_password():
    return "TestMasterP@ssw0rd!"


@pytest.fixture
def unlocked_vault(temp_vault_path, master_password):
    """Vault initialisé et déverrouillé avec une entrée vide."""
    v = Vault(vault_path=temp_vault_path)
    v.init(master_password)
    return v
