"""Password manager logic: hashing, encryption, password generator and PasswordManager."""

import base64
import hashlib
import json
import os
import secrets
import string

from cryptography.fernet import Fernet

ITERATIONS = 200_000

SPECIAL_CHARS = "!@#$%^&*()-_=+?"


def make_salt() -> str:
    """Return a new random salt (16 bytes) as a hex string."""
    return os.urandom(16).hex()


def _pbkdf2(password: str, salt: str) -> bytes:
    """Run PBKDF2-SHA256 for the password and the salt, return 32 raw bytes."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), ITERATIONS)


def hash_password(password: str, salt: str) -> str:
    """Return the hash of the password as a hex string."""
    return _pbkdf2(password, salt).hex()


def check_password(password: str, salt: str, expected_hash: str) -> bool:
    """Check that the password gives the same hash as the saved one."""
    new_hash = hash_password(password, salt)

    return new_hash == expected_hash


def make_key(password: str, salt: str) -> bytes:
    """Make an encryption key for Fernet from the master password and a salt."""
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

    if length < 4:
        raise ValueError("Длина пароля должна быть не меньше 4 символов.")

    alphabet = string.ascii_letters + string.digits + SPECIAL_CHARS

    while True:
        password = ""
        for _ in range(length):
            password += secrets.choice(alphabet)
        if is_strong(password):
            return password


MIN_MASTER_LENGTH = 6


class VaultError(Exception):
    """Error with a clear message for the user (wrong name, locked vault and so on)."""


class PasswordManager:
    """Password vault stored in a JSON file.

    Structure of the file:
        {
          "master_salt": "...",   # salt for the master password hash
          "master_hash": "...",   # hash of the master password (not the password itself)
          "key_salt": "...",      # another salt, for the encryption key
          "entries": {"github": {"login": "...", "password": "<encrypted>"}}
        }
    """

    def __init__(self, path: str = "vault.json") -> None:
        """Create the manager and load the file if it already exists."""

        self.path = path

        self.master_salt = ""
        self.master_hash = ""
        self.key_salt = ""

        self.entries: dict[str, dict[str, str]] = {}

        self.key: bytes | None = None

        if os.path.exists(self.path):
            self._load()

    def is_initialized(self) -> bool:
        """Return True if the master password was already created."""
        return self.master_hash != ""

    def init_master(self, password: str, old_password: str | None = None) -> None:
        """Create the master password and an empty vault.

        If the vault already exists, it can be overwritten only with the current
        master password (old_password). All old entries are deleted in this case.
        """

        if self.is_initialized():
            if old_password is None or not self.unlock(old_password):
                raise VaultError(
                    "Хранилище уже создано. Перезаписать его можно только с текущим мастер-паролем."
                )

        if len(password) < MIN_MASTER_LENGTH:
            raise VaultError(f"Мастер-пароль должен быть не короче {MIN_MASTER_LENGTH} символов.")

        self.master_salt = make_salt()
        self.master_hash = hash_password(password, self.master_salt)

        self.key_salt = make_salt()

        self.entries = {}
        self.key = make_key(password, self.key_salt)
        self._persist()

    def unlock(self, password: str) -> bool:
        """Check the master password. If it is correct, make the key and return True."""
        if not self.is_initialized():
            return False

        if not check_password(password, self.master_salt, self.master_hash):
            return False

        self.key = make_key(password, self.key_salt)
        return True

    def add_entry(self, name: str, login: str, pwd: str) -> None:
        """Add a new entry. The password is saved encrypted."""
        self._require_unlocked()

        if name == "":
            raise VaultError("Название записи не может быть пустым.")
        if name in self.entries:
            raise VaultError(f"Запись '{name}' уже существует.")

        self.entries[name] = {"login": login, "password": encrypt(pwd, self._get_key())}

        self._persist()

    def list_entries(self) -> list[str]:
        """Return names of all entries (without passwords), sorted by name."""
        self._require_unlocked()

        return sorted(self.entries)

    def get_entry(self, name: str) -> tuple[str, str]:
        """Return (login, password) of the entry. The password is decrypted."""
        self._require_unlocked()

        if name not in self.entries:
            raise VaultError(f"Записи '{name}' нет.")

        entry = self.entries[name]
        pwd = decrypt(entry["password"], self._get_key())
        return entry["login"], pwd

    def delete_entry(self, name: str) -> None:
        """Delete the entry by its name."""
        self._require_unlocked()
        if name not in self.entries:
            raise VaultError(f"Записи '{name}' нет.")
        del self.entries[name]
        self._persist()

    def _require_unlocked(self) -> None:
        """Raise an error if the vault is locked (master password not entered)."""
        if self.key is None:
            raise VaultError("Хранилище закрыто: сначала введите мастер-пароль.")

    def _get_key(self) -> bytes:
        """Return the key or raise an error if the vault is locked."""
        if self.key is None:
            raise VaultError("Хранилище закрыто: сначала введите мастер-пароль.")
        return self.key

    def _persist(self) -> None:
        """Save everything to the JSON file. The key itself is never saved."""
        data = {
            "master_salt": self.master_salt,
            "master_hash": self.master_hash,
            "key_salt": self.key_salt,
            "entries": self.entries,
        }
        with open(self.path, "w", encoding="utf-8") as file:
            json.dump(data, file, ensure_ascii=False, indent=2)

    def _load(self) -> None:
        """Read the JSON file. Raise VaultError if the file is broken."""
        try:
            with open(self.path, encoding="utf-8") as file:
                data = json.load(file)

            self.master_salt = data["master_salt"]
            self.master_hash = data["master_hash"]
            self.key_salt = data["key_salt"]
            self.entries = data["entries"]

        except Exception:
            raise VaultError(f"Файл {self.path} повреждён или имеет неверный формат.")
