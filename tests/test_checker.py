import pytest
import asyncio
from unittest.mock import MagicMock
from checker import PasswordChecker, PasswordSecurityError, SecurityLevel
from aioresponses import aioresponses

@pytest.fixture
async def checker():
    """Fixture to initialize PasswordChecker"""
    checker = PasswordChecker(enable_logging=False)
    async with checker:
        yield checker

@pytest.mark.asyncio
async def test_hash_password(checker):
    """Test SHA1 hashing of password"""
    prefix, suffix = checker._hash_password("password123")
    # SHA1 of "password123" is CBFDAAC6008F9CAB40833284EA118562862F1E09
    assert prefix == "CBFDA"
    assert suffix == "AC6008F9CAB40833284EA118562862F1E09"

@pytest.mark.asyncio
async def test_analyze_password_strength_strong(checker):
    """Test analysis of a strong password"""
    strong_pwd = "StrongPassword123!"
    analysis = checker._analyze_password_strength(strong_pwd)
    
    assert analysis['score'] >= 7  # Should pass most checks
    assert analysis['level'] in [SecurityLevel.STRONG, SecurityLevel.EXCELLENT]
    assert analysis['checks']['length'] is True
    assert analysis['checks']['uppercase'] is True
    assert analysis['checks']['lowercase'] is True
    assert analysis['checks']['digits'] is True
    assert analysis['checks']['special_chars'] is True

@pytest.mark.asyncio
async def test_analyze_password_strength_weak(checker):
    """Test analysis of a weak password"""
    weak_pwd = "123"
    analysis = checker._analyze_password_strength(weak_pwd)
    
    assert analysis['level'] == SecurityLevel.CRITICAL
    assert analysis['checks']['length'] is False
    assert analysis['checks']['uppercase'] is False
    assert analysis['checks']['special_chars'] is False

@pytest.mark.asyncio
async def test_count_breaches(checker):
    """Test parsing of HIBP API response"""
    # Mock response from HIBP: suffix:count
    mock_response = "AC6008F9CAB40833284EA118562862F1E09:5\nOTHERHASH:10"
    suffix = "AC6008F9CAB40833284EA118562862F1E09"
    
    count = checker._count_breaches(mock_response, suffix)
    assert count == 5

@pytest.mark.asyncio
async def test_count_breaches_not_found(checker):
    """Test parsing when hash is not in response"""
    mock_response = "OTHERHASH:10"
    suffix = "AC6008F9CAB40833284EA118562862F1E09"
    
    count = checker._count_breaches(mock_response, suffix)
    assert count == 0

@pytest.mark.asyncio
async def test_check_password_breached(checker):
    """Test full check flow for a breached password"""
    pwd = "password123"
    prefix = "CBFDA"
    suffix = "AC6008F9CAB40833284EA118562862F1E09"
    
    with aioresponses() as m:
        # Mock the API call
        m.get(f"https://api.pwnedpasswords.com/range/{prefix}", 
              status=200, 
              body=f"{suffix}:1000")
        
        result = await checker.check_password(pwd)
        
        assert result.breach_count == 1000
        assert result.security_level == SecurityLevel.CRITICAL

@pytest.mark.asyncio
async def test_check_password_safe(checker):
    """Test full check flow for a safe password"""
    pwd = "UniqueComplexPassword999!"
    prefix, _ = checker._hash_password(pwd)
    
    with aioresponses() as m:
        # Mock empty response or response without our hash
        m.get(f"https://api.pwnedpasswords.com/range/{prefix}", 
              status=200, 
              body="OTHERHASH:1")
        
        result = await checker.check_password(pwd)
        
        assert result.breach_count == 0
        # Should be strong based on complexity
        assert result.security_level in [SecurityLevel.STRONG, SecurityLevel.EXCELLENT]

@pytest.mark.asyncio
async def test_api_failure_handling(checker):
    """Test graceful handling of API failures"""
    pwd = "password123"
    prefix, _ = checker._hash_password(pwd)
    
    with aioresponses() as m:
        # Mock 500 error
        m.get(f"https://api.pwnedpasswords.com/range/{prefix}", 
              status=500, 
              repeat=True) # Repeat for retries
        
        # Should catch PasswordSecurityError internally and return breach_count = -1
        result = await checker.check_password(pwd)
        
        assert result.breach_count == -1
