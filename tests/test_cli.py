import argparse
import asyncio
import io
import sys
from unittest.mock import AsyncMock, patch, MagicMock
import pytest
from cli import main
from models import PasswordAnalysis, SecurityLevel

@pytest.fixture
def mock_checker():
    with patch('cli.PasswordChecker') as MockChecker:
        # Create a MagicMock but with __aenter__ and __aexit__ for async context manager
        mock_instance = MagicMock()
        mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_instance.__aexit__ = AsyncMock(return_value=None)
        
        # Explicitly set async methods
        mock_instance.check_password = AsyncMock()
        mock_instance.check_passwords_batch = AsyncMock()
        
        # format_result is synchronous, so MagicMock handles it correctly by default
        
        MockChecker.return_value = mock_instance
        yield mock_instance

@pytest.fixture
def mock_print():
    with patch('builtins.print') as mock:
        yield mock

@pytest.fixture
def mock_getpass():
    with patch('getpass.getpass') as mock:
        yield mock

@pytest.mark.asyncio
async def test_interactive_mode_success(mock_checker, mock_print, mock_getpass):
    mock_getpass.return_value = "securepassword123"
    
    mock_analysis = PasswordAnalysis(
        password_hash="hash",
        breach_count=0,
        security_level=SecurityLevel.STRONG,
        strength_score=10,
        feedback=[],
        local_checks={},
        response_time=0.1
    )
    mock_checker.check_password.return_value = mock_analysis
    mock_checker.format_result.return_value = "Mock Result"

    with patch('sys.argv', ['cli.py', '-i']):
        exit_code = await main()
        
    assert exit_code == 0
    mock_getpass.assert_called_once()
    mock_checker.check_password.assert_called_once_with("securepassword123")
    mock_print.assert_any_call("Mock Result")

@pytest.mark.asyncio
async def test_interactive_mode_no_password(mock_checker, mock_print, mock_getpass):
    mock_getpass.return_value = ""
    
    with patch('sys.argv', ['cli.py', '-i']):
        exit_code = await main()
        
    assert exit_code == 1
    mock_print.assert_any_call("No password entered.")
    mock_checker.check_password.assert_not_called()

@pytest.mark.asyncio
async def test_file_mode(mock_checker, mock_print):
    mock_analysis = PasswordAnalysis(
        password_hash="hash",
        breach_count=0,
        security_level=SecurityLevel.STRONG,
        strength_score=10,
        feedback=[],
        local_checks={},
        response_time=0.1
    )
    mock_checker.check_passwords_batch.return_value = [mock_analysis]
    mock_checker.format_result.return_value = "Mock Result"

    with patch('sys.argv', ['cli.py', '-f', 'passwords.txt']), \
         patch('cli.load_passwords_from_file', return_value=['password123']):
        exit_code = await main()
        
    assert exit_code == 0
    # In file mode with 1 password, it might use check_password or check_passwords_batch depending on logic.
    # The code says: if len(passwords) == 1: check_password
    # So we should expect check_password, not check_passwords_batch if list has 1 item.
    # Let's check cli.py logic again.
    
    # Actually, let's update the test to expect check_password if only 1 password is loaded.
    mock_checker.check_password.assert_called_once_with('password123')

@pytest.mark.asyncio
async def test_batch_mode_weak_password(mock_checker, mock_print):
    mock_analysis = PasswordAnalysis(
        password_hash="hash",
        breach_count=5,
        security_level=SecurityLevel.CRITICAL,
        strength_score=2,
        feedback=["Weak"],
        local_checks={},
        response_time=0.1
    )
    # Batch mode with 1 password still hits `if len(passwords) == 1:` block
    mock_checker.check_password.return_value = mock_analysis
    mock_checker.format_result.return_value = "Mock Result"

    with patch('sys.argv', ['cli.py', '-b', 'weakpass']):
        exit_code = await main()
        
    assert exit_code == 1  # Should return 1 for weak passwords
    mock_print.assert_any_call("Mock Result")

@pytest.mark.asyncio
async def test_no_args_shows_help(mock_checker, mock_print):
    # When no args are provided, argparse prints help and exits.
    # We can't easily test system exit here unless we catch it,
    # but let's test that main handles empty args correctly if argparse allows it.
    # Actually, argparse will exit if required args are missing, but here 'passwords' is nargs='*'.
    # If no passwords provided, it prints "No passwords to check." and returns 1.
    
    with patch('sys.argv', ['cli.py']):
        exit_code = await main()
        
    assert exit_code == 1
    mock_print.assert_any_call("No passwords to check.")
