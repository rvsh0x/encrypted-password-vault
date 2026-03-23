"""Tests du stockage : lecture/écriture vault, format versionné."""

import json
import tempfile
import os
import base64
import pytest

from password_manager.storage import (
    vault_file_path,
    vault_exists,
    read_vault_file,
    write_vault_file,
    decode_salt_from_vault,
    decode_encrypted_data_from_vault,
    VAULT_VERSION_KEY,
    VAULT_SALT_KEY,
    VAULT_DATA_KEY,
)
from password_manager.models import VAULT_FORMAT_VERSION


def test_vault_file_path_default():
    p = vault_file_path(None)
    assert p.name == "vault.enc"


def test_vault_file_path_custom():
    p = vault_file_path("/tmp/custom.enc")
    assert str(p) == "/tmp/custom.enc"


def test_write_and_read_vault():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "v.enc")
        salt_b64 = base64.b64encode(b"x" * 32).decode("ascii")
        data_b64 = base64.b64encode(b"encrypted_payload").decode("ascii")
        write_vault_file(salt_b64, data_b64, vault_path=path, version=1)
        assert os.path.exists(path)
        raw = read_vault_file(path)
        assert raw[VAULT_VERSION_KEY] == 1
        assert raw[VAULT_SALT_KEY] == salt_b64
        assert raw[VAULT_DATA_KEY] == data_b64


def test_decode_salt_and_data():
    salt = b"random_salt_32_bytes!!!!!!!!!!!!!"
    salt_b64 = base64.b64encode(salt).decode("ascii")
    raw = {VAULT_VERSION_KEY: 1, VAULT_SALT_KEY: salt_b64, VAULT_DATA_KEY: "YQ=="}
    assert decode_salt_from_vault(raw) == salt
    assert decode_encrypted_data_from_vault(raw) == "YQ=="


def test_read_vault_missing_raises():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "nonexistent.enc")
        with pytest.raises(FileNotFoundError):
            read_vault_file(path)


def test_read_vault_invalid_version_raises():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "v.enc")
        with open(path, "w") as f:
            json.dump({VAULT_VERSION_KEY: 99, VAULT_SALT_KEY: "YQ==", VAULT_DATA_KEY: "YQ=="}, f)
        with pytest.raises(ValueError, match="non supporté"):
            read_vault_file(path)
