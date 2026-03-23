"""Tests du générateur de mots de passe."""

import string
import pytest

from password_manager.password_generator import generate_password


def test_length():
    p = generate_password(length=16)
    assert len(p) == 16
    p2 = generate_password(length=32)
    assert len(p2) == 32


def test_min_length_enforced():
    p = generate_password(length=2)
    assert len(p) >= 4


def test_default_has_all_categories():
    p = generate_password(length=50)
    has_upper = any(c in string.ascii_uppercase for c in p)
    has_lower = any(c in string.ascii_lowercase for c in p)
    has_digit = any(c in string.digits for c in p)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in p)
    assert has_upper
    assert has_lower
    assert has_digit
    assert has_special


def test_no_special():
    p = generate_password(length=30, use_special=False)
    assert all(c in string.ascii_letters + string.digits for c in p)


def test_different_each_time():
    seen = {generate_password(length=20) for _ in range(10)}
    assert len(seen) == 10
