# Менеджер паролей в терминале

Лабораторная работа 1, трек DevOps, тема **Б1**.

Программа хранит пароли от сайтов в файле `vault.json`. Вход по мастер-паролю.

- Мастер-пароль **не хранится**. В файле лежит только его хэш (PBKDF2-SHA256 со случайной солью).
- Пароли записей **зашифрованы** (Fernet из библиотеки `cryptography`). Ключ шифрования
  получается из мастер-пароля и живёт только в памяти, в файл не пишется.
- Пароли вводятся скрыто (`getpass`).
- Есть генератор надёжных паролей.

## Структура

```
password_manager.py      # точка входа: python password_manager.py ...
passman/
    manager.py           # соль, хэш, шифрование, генератор + класс PasswordManager
    cli.py               # аргументы командной строки и меню
tests/                   # тесты pytest
.github/workflows/ci.yml # GitHub Actions: ruff, mypy, pytest на каждый push
```

## Установка

С [uv](https://docs.astral.sh/uv/):

```
uv sync
```

Или через обычный pip:

```
pip install cryptography pytest ruff mypy
```

## Запуск

```
uv run python password_manager.py --init       # создать мастер-пароль
uv run python password_manager.py --unlock     # войти и открыть меню
uv run python password_manager.py --generate   # сгенерировать пароль (--length 20)
```

Без uv то же самое, только `python password_manager.py ...`.

Другой файл хранилища: `--vault my_vault.json`.

Команды меню после входа:

| Команда            | Что делает                                          |
| ------------------ | --------------------------------------------------- |
| `add`              | добавить запись (пустой пароль = сгенерировать)     |
| `list`             | показать названия записей (без паролей)             |
| `get <название>`   | показать логин и пароль (спросит мастер-пароль)     |
| `delete <название>`| удалить запись                                      |
| `exit`             | выход                                               |

Запускайте в обычном терминале (cmd, PowerShell, терминал VS Code). В консоли «Run»
некоторых IDE скрытый ввод пароля может не работать.

## Проверки

```
uv run pytest                  # тесты
uv run ruff check .            # линтер
uv run ruff format --check .   # форматирование
uv run mypy                    # проверка типов (strict)
```
