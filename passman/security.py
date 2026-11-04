"""Security helpers: salt, password hashing, encryption and password generation."""

import base64
import hashlib
import hmac
import os
import secrets
import string

from cryptography.fernet import Fernet

# Сколько раз PBKDF2 повторяет хэширование.
# Чем больше число, тем медленнее перебор паролей для взломщика.
ITERATIONS = 200_000

# Спецсимволы, которые использует генератор паролей.
SPECIAL_CHARS = "!@#$%^&*()-_=+?"


def make_salt() -> str:
    """Return a new random salt (16 bytes) as a hex string."""
    # os.urandom берёт случайные байты у операционной системы.
    # .hex() превращает байты в строку вида "a3f09c...", чтобы её можно было сохранить в JSON.
    return os.urandom(16).hex()


def _pbkdf2(password: str, salt: str) -> bytes:
    """Run PBKDF2-SHA256 for the password and the salt, return 32 raw bytes."""
    # password.encode() -> байты пароля, bytes.fromhex(salt) -> байты соли.
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), ITERATIONS)


def hash_password(password: str, salt: str) -> str:
    """Return the hash of the password as a hex string."""
    return _pbkdf2(password, salt).hex()


def check_password(password: str, salt: str, expected_hash: str) -> bool:
    """Check that the password gives the same hash as the saved one."""
    new_hash = hash_password(password, salt)
    # compare_digest сравнивает строки за одинаковое время,
    # поэтому по времени ответа нельзя угадать, сколько символов совпало.
    return hmac.compare_digest(new_hash, expected_hash)


def make_key(password: str, salt: str) -> bytes:
    """Make an encryption key for Fernet from the master password and a salt."""
    # Fernet требует ключ: 32 байта, записанные в формате base64.
    return base64.urlsafe_b64encode(_pbkdf2(password, salt))


def encrypt(text: str, key: bytes) -> str:
    """Encrypt the text with the key and return the result as a string."""
    token = Fernet(key).encrypt(text.encode())
    return token.decode()


def decrypt(token: str, key: bytes) -> str:
    """Decrypt the string made by encrypt(). Raises InvalidToken if the key is wrong."""
    text = Fernet(key).decrypt(token.encode())
    return text.decode()


def is_strong(password: str) -> bool:
    """Return True if the password has a lowercase, uppercase, digit and special char."""
    has_lower = False
    has_upper = False
    has_digit = False
    has_special = False
    for char in password:
        if char.islower():
            has_lower = True
        elif char.isupper():
            has_upper = True
        elif char.isdigit():
            has_digit = True
        elif char in SPECIAL_CHARS:
            has_special = True
    return has_lower and has_upper and has_digit and has_special


def generate_password(length: int = 16) -> str:
    """Generate a random strong password of the given length."""
    # Меньше 4 символов не хватит, чтобы вместить все 4 вида символов.
    if length < 4:
        raise ValueError("Длина пароля должна быть не меньше 4 символов.")

    alphabet = string.ascii_letters + string.digits + SPECIAL_CHARS
    # Генерируем пароль, пока не получится такой, где есть все виды символов.
    # Обычно это получается с первой-второй попытки.
    while True:
        password = ""
        for _ in range(length):
            # secrets, а не random: random предсказуем и не подходит для паролей.
            password += secrets.choice(alphabet)
        if is_strong(password):
            return password
