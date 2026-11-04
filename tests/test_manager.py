"""Tests for PasswordManager (no real keyboard input, only class methods)."""

from pathlib import Path

import pytest

from passman.manager import PasswordManager, VaultError

MASTER = "master-123"


def make_vault(tmp_path: Path) -> PasswordManager:
    """Create a new vault in a temporary folder with the MASTER password."""
    manager = PasswordManager(str(tmp_path / "vault.json"))
    manager.init_master(MASTER)
    return manager


def test_unlock_with_correct_password(tmp_path: Path) -> None:
    make_vault(tmp_path)
    # Новый объект читает файл заново, как при повторном запуске программы.
    manager = PasswordManager(str(tmp_path / "vault.json"))
    assert manager.unlock(MASTER) is True


def test_unlock_with_wrong_password(tmp_path: Path) -> None:
    make_vault(tmp_path)
    manager = PasswordManager(str(tmp_path / "vault.json"))
    assert manager.unlock("wrong-password") is False


def test_second_init_without_password_fails(tmp_path: Path) -> None:
    make_vault(tmp_path)
    manager = PasswordManager(str(tmp_path / "vault.json"))
    with pytest.raises(VaultError):
        manager.init_master("new-master-456")
    with pytest.raises(VaultError):
        manager.init_master("new-master-456", "wrong-password")
    # Старый мастер-пароль всё ещё работает — файл не перезаписан.
    assert manager.unlock(MASTER) is True


def test_second_init_with_correct_password_works(tmp_path: Path) -> None:
    make_vault(tmp_path)
    manager = PasswordManager(str(tmp_path / "vault.json"))
    manager.init_master("new-master-456", MASTER)
    assert manager.unlock("new-master-456") is True
    assert manager.unlock(MASTER) is False


def test_add_list_get(tmp_path: Path) -> None:
    manager = make_vault(tmp_path)
    manager.add_entry("github", "denis", "gh-secret-1")
    assert manager.list_entries() == ["github"]
    assert manager.get_entry("github") == ("denis", "gh-secret-1")


def test_entries_are_saved_to_file(tmp_path: Path) -> None:
    manager = make_vault(tmp_path)
    manager.add_entry("mail", "denis@mail.ru", "mail-secret-2")
    # Открываем файл заново: запись должна сохраниться.
    reopened = PasswordManager(str(tmp_path / "vault.json"))
    reopened.unlock(MASTER)
    assert reopened.get_entry("mail") == ("denis@mail.ru", "mail-secret-2")


def test_delete_removes_entry(tmp_path: Path) -> None:
    manager = make_vault(tmp_path)
    manager.add_entry("github", "denis", "gh-secret-1")
    manager.delete_entry("github")
    assert manager.list_entries() == []
    with pytest.raises(VaultError):
        manager.get_entry("github")


def test_add_same_name_twice_fails(tmp_path: Path) -> None:
    manager = make_vault(tmp_path)
    manager.add_entry("github", "denis", "gh-secret-1")
    with pytest.raises(VaultError):
        manager.add_entry("github", "other", "other-secret")


def test_locked_vault_gives_error(tmp_path: Path) -> None:
    make_vault(tmp_path)
    manager = PasswordManager(str(tmp_path / "vault.json"))
    # unlock() не вызывали — ключа нет.
    with pytest.raises(VaultError):
        manager.list_entries()


def test_file_has_no_plain_passwords(tmp_path: Path) -> None:
    manager = make_vault(tmp_path)
    manager.add_entry("github", "denis", "gh-secret-1")
    text = (tmp_path / "vault.json").read_text(encoding="utf-8")
    assert MASTER not in text
    assert "gh-secret-1" not in text
    # Логин и название не секретные, они хранятся открыто.
    assert "github" in text


def test_salt_is_random(tmp_path: Path) -> None:
    first = PasswordManager(str(tmp_path / "first.json"))
    first.init_master(MASTER)
    second = PasswordManager(str(tmp_path / "second.json"))
    second.init_master(MASTER)
    # Пароль одинаковый, но соли разные, значит и хэши разные.
    assert first.master_salt != second.master_salt
    assert first.master_hash != second.master_hash


def test_broken_file_gives_clear_error(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    path.write_text("это не json", encoding="utf-8")
    with pytest.raises(VaultError):
        PasswordManager(str(path))
