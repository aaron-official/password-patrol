from pathlib import Path
from checker import PasswordSecurityError

def load_passwords_from_file(file_path: Path):
    """Load passwords from a text file (one per line)"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        raise PasswordSecurityError(f"Could not read password file: {e}")
