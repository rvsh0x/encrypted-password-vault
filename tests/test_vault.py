"""Tests du coffre-fort : init, unlock, add, list, get, delete."""

import pytest

from password_manager.vault import Vault, VaultError
from password_manager.storage import vault_exists


def test_init_creates_vault(temp_vault_path, master_password):
    v = Vault(vault_path=temp_vault_path)
    v.init(master_password)
    assert not v.is_locked
    assert vault_exists(temp_vault_path)


def test_init_twice_fails(temp_vault_path, master_password):
    v = Vault(vault_path=temp_vault_path)
    v.init(master_password)
    with pytest.raises(VaultError, match="existe déjà"):
        v.init(master_password)


def test_unlock_wrong_password(temp_vault_path, master_password):
    v = Vault(vault_path=temp_vault_path)
    v.init(master_password)
    v.lock()
    with pytest.raises(VaultError, match="incorrect|corrompu"):
        v.unlock("WrongPassword")


def test_unlock_then_add_list(temp_vault_path, master_password):
    v = Vault(vault_path=temp_vault_path)
    v.init(master_password)
    v.add_entry("site1", "user1", "pass1", "notes1")
    v.lock()
    v.unlock(master_password)
    entries = v.list_entries()
    assert len(entries) == 1
    assert entries[0].site == "site1"
    assert entries[0].username == "user1"
    assert entries[0].password == "pass1"
    assert entries[0].notes == "notes1"


def test_get_entry_by_index(unlocked_vault):
    unlocked_vault.add_entry("a", "b", "c")
    e = unlocked_vault.get_entry_by_index(1)
    assert e is not None
    assert e.site == "a"
    e0 = unlocked_vault.get_entry_by_index(0)
    assert e0 is None
    e99 = unlocked_vault.get_entry_by_index(99)
    assert e99 is None


def test_delete_entry(unlocked_vault):
    unlocked_vault.add_entry("x", "y", "z")
    entries = unlocked_vault.list_entries()
    assert len(entries) == 1
    eid = entries[0].id
    ok = unlocked_vault.delete_entry(eid)
    assert ok is True
    assert len(unlocked_vault.list_entries()) == 0
    assert unlocked_vault.delete_entry("nonexistent") is False


def test_persist_after_add(temp_vault_path, master_password):
    v = Vault(vault_path=temp_vault_path)
    v.init(master_password)
    v.add_entry("persist", "u", "p")
    v.lock()
    v2 = Vault(vault_path=temp_vault_path)
    v2.unlock(master_password)
    entries = v2.list_entries()
    assert len(entries) == 1
    assert entries[0].site == "persist"
