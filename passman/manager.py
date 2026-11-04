"""PasswordManager class: keeps entries in a JSON file, passwords are encrypted."""

import json
import os

from cryptography.fernet import InvalidToken

from passman import security

# Минимальная длина мастер-пароля.
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
        # Ключ шифрования. Он есть только в памяти и только после unlock().
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

        # Две РАЗНЫЕ соли: одна для хэша, другая для ключа.
        # Если соль была бы одна, ключ совпал бы с хэшем, а хэш лежит в файле открыто.
        self.master_salt = security.make_salt()
        self.master_hash = security.hash_password(password, self.master_salt)
        self.key_salt = security.make_salt()
        self.entries = {}
        self.key = security.make_key(password, self.key_salt)
        self._persist()

    def unlock(self, password: str) -> bool:
        """Check the master password. If it is correct, make the key and return True."""
        if not self.is_initialized():
            return False
        if not security.check_password(password, self.master_salt, self.master_hash):
            return False
        self.key = security.make_key(password, self.key_salt)
        return True

    def add_entry(self, name: str, login: str, pwd: str) -> None:
        """Add a new entry. The password is saved encrypted."""
        key = self._get_key()
        if name == "":
            raise VaultError("Название записи не может быть пустым.")
        if name in self.entries:
            raise VaultError(f"Запись '{name}' уже существует.")
        self.entries[name] = {"login": login, "password": security.encrypt(pwd, key)}
        self._persist()

    def list_entries(self) -> list[str]:
        """Return names of all entries (without passwords), sorted by name."""
        self._get_key()
        # sorted(словарь) возвращает отсортированный список его ключей.
        return sorted(self.entries)

    def get_entry(self, name: str) -> tuple[str, str]:
        """Return (login, password) of the entry. The password is decrypted."""
        key = self._get_key()
        if name not in self.entries:
            raise VaultError(f"Записи '{name}' нет.")
        entry = self.entries[name]
        try:
            pwd = security.decrypt(entry["password"], key)
        except InvalidToken:
            raise VaultError("Не удалось расшифровать пароль: файл повреждён.") from None
        return entry["login"], pwd

    def delete_entry(self, name: str) -> None:
        """Delete the entry by its name."""
        self._get_key()
        if name not in self.entries:
            raise VaultError(f"Записи '{name}' нет.")
        del self.entries[name]
        self._persist()

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
        except (json.JSONDecodeError, KeyError, TypeError):
            raise VaultError(f"Файл {self.path} повреждён или имеет неверный формат.") from None
