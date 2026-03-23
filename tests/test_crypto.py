"""Tests du module crypto : dérivation de clé, chiffrement/déchiffrement."""

import pytest

from password_manager.crypto import (
    derive_key,
    generate_salt,
    encrypt,
    decrypt,
    encrypt_vault_data,
    decrypt_vault_data,
    SALT_LENGTH,
    NONCE_LENGTH,
    verify_password_constant_time,
)


def test_generate_salt_length():
    salt = generate_salt()
    assert len(salt) == SALT_LENGTH
    assert salt != generate_salt()


def test_derive_key_reproducible():
    salt = generate_salt()
    key1 = derive_key("password123", salt)
    key2 = derive_key("password123", salt)
    assert key1 == key2
    assert len(key1) == 32


def test_derive_key_different_salt():
    salt1 = generate_salt()
    salt2 = generate_salt()
    key1 = derive_key("same", salt1)
    key2 = derive_key("same", salt2)
    assert key1 != key2


def test_derive_key_different_password():
    salt = generate_salt()
    key1 = derive_key("pass1", salt)
    key2 = derive_key("pass2", salt)
    assert key1 != key2


def test_encrypt_decrypt_roundtrip():
    key = b"0" * 32
    plaintext = b"secret data"
    nonce, ciphertext = encrypt(plaintext, key)
    assert len(nonce) == NONCE_LENGTH
    assert ciphertext != plaintext
    decrypted = decrypt(nonce, ciphertext, key)
    assert decrypted == plaintext


def test_encrypt_different_nonce_each_time():
    key = b"0" * 32
    c1 = encrypt(b"data", key)
    c2 = encrypt(b"data", key)
    assert c1[0] != c2[0]
    assert c1[1] != c2[1]


def test_decrypt_wrong_key_fails():
    salt = generate_salt()
    key = derive_key("right", salt)
    nonce, ciphertext = encrypt(b"secret", key)
    wrong_key = derive_key("wrong", salt)
    with pytest.raises(Exception):
        decrypt(nonce, ciphertext, wrong_key)


def test_encrypt_vault_data_decrypt_roundtrip():
    key = b"a" * 32
    json_str = '[{"site":"example.com","username":"u","password":"p"}]'
    encoded = encrypt_vault_data(json_str, key)
    assert isinstance(encoded, str)
    decoded = decrypt_vault_data(encoded, key)
    assert decoded == json_str


def test_decrypt_vault_data_tampered_fails():
    key = b"a" * 32
    encoded = encrypt_vault_data("data", key)
    tampered = encoded[:-2] + "xx"
    with pytest.raises(Exception):
        decrypt_vault_data(tampered, key)


def test_constant_time_compare():
    a = b"same"
    b = b"same"
    c = b"diff"
    assert verify_password_constant_time(a, b) is True
    assert verify_password_constant_time(a, c) is False
    assert verify_password_constant_time(b"", b"") is True
