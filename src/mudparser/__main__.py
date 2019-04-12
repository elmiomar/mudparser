"""
Entry point for running mudparser as a module.

Usage:
    python -m mudparser --help
    python -m mudparser validate file.json
    python -m mudparser info file.json
"""

from mudparser.cli import app

if __name__ == "__main__":
    app()
