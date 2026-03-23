"""Tests des modèles PasswordEntry et VaultMetadata."""

import json
import pytest

from password_manager.models import PasswordEntry, VaultMetadata, VAULT_FORMAT_VERSION


def test_password_entry_to_dict():
    e = PasswordEntry(site="x.com", username="u", password="p", notes="n", id="123")
    d = e.to_dict()
    assert d["site"] == "x.com"
    assert d["username"] == "u"
    assert d["password"] == "p"
    assert d["notes"] == "n"
    assert d["id"] == "123"


def test_password_entry_from_dict():
    d = {"site": "a", "username": "b", "password": "c", "notes": "d", "id": "i"}
    e = PasswordEntry.from_dict(d)
    assert e.site == "a"
    assert e.username == "b"
    assert e.password == "c"
    assert e.notes == "d"
    assert e.id == "i"


def test_password_entry_roundtrip_json():
    e = PasswordEntry(site="s", username="u", password="p", notes=None)
    e2 = PasswordEntry.from_json(e.to_json())
    assert e2.site == e.site
    assert e2.username == e.username
    assert e2.password == e.password
    assert e2.notes == e.notes


def test_vault_metadata_version():
    m = VaultMetadata.from_dict({"version": 1})
    assert m.version == 1
    assert VaultMetadata.from_dict({}).version == VAULT_FORMAT_VERSION
