"""Entry point: python password_manager.py --init | --unlock | --generate."""

import sys

from passman.cli import main

if __name__ == "__main__":
    sys.exit(main())
