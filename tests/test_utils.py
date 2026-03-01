import pytest
from pathlib import Path
from utils import load_passwords_from_file
from checker import PasswordSecurityError

def test_load_passwords_from_file(tmp_path):
    """Test loading passwords from a temporary file"""
    # Create a dummy password file
    p = tmp_path / "passwords.txt"
    p.write_text("password123\nSecretPass!\n  \n", encoding="utf-8")
    
    passwords = load_passwords_from_file(p)
    
    assert len(passwords) == 2
    assert passwords[0] == "password123"
    assert passwords[1] == "SecretPass!"

def test_load_passwords_file_not_found():
    """Test loading a non-existent file raises error"""
    with pytest.raises(PasswordSecurityError):
        load_passwords_from_file(Path("nonexistent.txt"))
