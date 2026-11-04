"""Command line interface: command line arguments and the interactive menu."""

import argparse
import getpass

from passman import security
from passman.manager import PasswordManager, VaultError

HELP_TEXT = "Команды: add, list, get <название>, delete <название>, help, exit"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Read command line arguments."""
    parser = argparse.ArgumentParser(description="Менеджер паролей в терминале.")
    # Ровно один из трёх режимов обязателен.
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--init", action="store_true", help="создать мастер-пароль")
    mode.add_argument("--unlock", action="store_true", help="войти и открыть меню")
    mode.add_argument("--generate", action="store_true", help="сгенерировать надёжный пароль")
    parser.add_argument("--length", type=int, default=16, help="длина пароля для --generate")
    parser.add_argument("--vault", default="vault.json", help="файл хранилища (vault.json)")
    return parser.parse_args(argv)


def command_init(manager: PasswordManager) -> None:
    """Create the master password (or overwrite the vault with the current one)."""
    old_password: str | None = None
    if manager.is_initialized():
        print("Хранилище уже существует. При перезаписи все записи будут удалены!")
        old_password = getpass.getpass("Текущий мастер-пароль: ")

    password = getpass.getpass("Новый мастер-пароль: ")
    repeat = getpass.getpass("Повторите мастер-пароль: ")
    if password != repeat:
        print("Пароли не совпадают.")
        return

    manager.init_master(password, old_password)
    print("Мастер-пароль создан. Теперь можно войти: --unlock")


def command_unlock(manager: PasswordManager) -> None:
    """Ask the master password and open the menu."""
    if not manager.is_initialized():
        print("Хранилище ещё не создано. Сначала запустите программу с --init")
        return

    password = getpass.getpass("Мастер-пароль: ")
    if not manager.unlock(password):
        print("Неверный мастер-пароль.")
        return

    print("Хранилище открыто.")
    print(HELP_TEXT)
    run_menu(manager)


def run_menu(manager: PasswordManager) -> None:
    """Read commands from the user until 'exit'."""
    while True:
        line = input("> ").strip()
        # "get github" -> ["get", "github"], "list" -> ["list"]
        parts = line.split(maxsplit=1)
        if len(parts) == 0:
            continue

        command = parts[0]
        name = ""
        if len(parts) == 2:
            name = parts[1]

        if command == "exit":
            print("До свидания!")
            break

        # Ошибки одной команды не роняют программу: печатаем и ждём следующую.
        try:
            handle_command(manager, command, name)
        except VaultError as error:
            print(f"Ошибка: {error}")


def handle_command(manager: PasswordManager, command: str, name: str) -> None:
    """Run one menu command."""
    if command == "add":
        menu_add(manager)
    elif command == "list":
        menu_list(manager)
    elif command == "get":
        menu_get(manager, name)
    elif command == "delete":
        menu_delete(manager, name)
    elif command == "help":
        print(HELP_TEXT)
    else:
        print(f"Неизвестная команда '{command}'. {HELP_TEXT}")


def ask_name(name: str) -> str:
    """Return the name, or ask it if it was not written after the command."""
    if name == "":
        name = input("Название записи: ").strip()
    return name


def menu_add(manager: PasswordManager) -> None:
    """Menu command 'add': add a new entry."""
    name = input("Название (например, github): ").strip()
    login = input("Логин: ").strip()
    pwd = getpass.getpass("Пароль (оставьте пустым, чтобы сгенерировать): ")
    if pwd == "":
        pwd = security.generate_password()
        print(f"Сгенерирован пароль: {pwd}")
    manager.add_entry(name, login, pwd)
    print(f"Запись '{name}' добавлена.")


def menu_list(manager: PasswordManager) -> None:
    """Menu command 'list': show names of the entries, but not passwords."""
    names = manager.list_entries()
    if len(names) == 0:
        print("Записей пока нет.")
        return
    for number, name in enumerate(names, start=1):
        print(f"{number}. {name}")


def menu_get(manager: PasswordManager, name: str) -> None:
    """Menu command 'get': show the password after the master password check."""
    name = ask_name(name)
    confirm = getpass.getpass("Подтвердите мастер-паролем: ")
    if not manager.unlock(confirm):
        print("Неверный мастер-пароль.")
        return
    login, pwd = manager.get_entry(name)
    print(f"Логин:  {login}")
    print(f"Пароль: {pwd}")


def menu_delete(manager: PasswordManager, name: str) -> None:
    """Menu command 'delete': delete the entry after a question."""
    name = ask_name(name)
    answer = input(f"Удалить запись '{name}'? (y/n): ").strip().lower()
    if answer != "y":
        print("Отменено.")
        return
    manager.delete_entry(name)
    print(f"Запись '{name}' удалена.")


def main(argv: list[str] | None = None) -> int:
    """Start the program. Return the exit code: 0 is success, 1 is error."""
    args = parse_args(argv)
    try:
        if args.generate:
            print(security.generate_password(args.length))
            return 0
        manager = PasswordManager(args.vault)
        if args.init:
            command_init(manager)
        else:
            command_unlock(manager)
    except (VaultError, ValueError) as error:
        # Понятное сообщение вместо длинного трейсбека.
        print(f"Ошибка: {error}")
        return 1
    except (KeyboardInterrupt, EOFError):
        # Ctrl+C или Ctrl+D (Ctrl+Z на Windows) — просто выходим.
        print("\nВыход.")
    return 0
