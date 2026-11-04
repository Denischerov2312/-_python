"""Tests for security helpers: hashing, encryption and password generator."""

import pytest
from cryptography.fernet import InvalidToken

from passman import security


def test_hash_depends_on_salt() -> None:
    salt_1 = security.make_salt()
    salt_2 = security.make_salt()
    # Одинаковые пароль и соль -> одинаковый хэш.
    assert security.hash_password("abc123", salt_1) == security.hash_password("abc123", salt_1)
    # Другая соль -> другой хэш.
    assert security.hash_password("abc123", salt_1) != security.hash_password("abc123", salt_2)


def test_check_password() -> None:
    salt = security.make_salt()
    saved_hash = security.hash_password("abc123", salt)
    assert security.check_password("abc123", salt, saved_hash) is True
    assert security.check_password("abc124", salt, saved_hash) is False


def test_encrypt_and_decrypt() -> None:
    key = security.make_key("abc123", security.make_salt())
    encrypted = security.encrypt("hello", key)
    assert encrypted != "hello"
    assert security.decrypt(encrypted, key) == "hello"


def test_decrypt_with_wrong_key_fails() -> None:
    salt = security.make_salt()
    right_key = security.make_key("abc123", salt)
    wrong_key = security.make_key("other", salt)
    encrypted = security.encrypt("hello", right_key)
    with pytest.raises(InvalidToken):
        security.decrypt(encrypted, wrong_key)


def test_generate_password() -> None:
    generated = security.generate_password(20)
    assert len(generated) == 20
    assert security.is_strong(generated) is True


def test_generate_password_too_short() -> None:
    with pytest.raises(ValueError):
        security.generate_password(3)


def test_is_strong() -> None:
    assert security.is_strong("Abc1!") is True
    assert security.is_strong("abc1!") is False  # нет заглавной
    assert security.is_strong("Abcd!") is False  # нет цифры
    assert security.is_strong("Abc12") is False  # нет спецсимвола
