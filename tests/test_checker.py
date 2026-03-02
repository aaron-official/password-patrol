import pytest
import pytest_asyncio
import asyncio
from unittest.mock import MagicMock
from checker import PasswordChecker, PasswordSecurityError, SecurityLevel
from aioresponses import aioresponses

@pytest_asyncio.fixture
async def checker():
    """Fixture to initialize PasswordChecker"""
    checker = PasswordChecker(enable_logging=False)
    async with checker:
        yield checker

@pytest.mark.asyncio
async def test_hash_password(checker):
    """Test SHA1 hashing of password"""
    prefix, suffix = checker._hash_password("password123")
    # SHA1 of "password123" is CBFDAC6008F9CAB4083784CBD1874F76618D2A97
    assert prefix == "CBFDA"
    assert suffix == "C6008F9CAB4083784CBD1874F76618D2A97"

@pytest.mark.asyncio
async def test_analyze_password_strength_strong(checker):
    """Test analysis of a strong password"""
    strong_pwd = "StrongPassword941!"
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
    # Real suffix for password123: C6008F9CAB4083784CBD1874F76618D2A97
    suffix = "C6008F9CAB4083784CBD1874F76618D2A97"
    mock_response = f"{suffix}:5\nOTHERHASH:10"
    
    count = checker._count_breaches(mock_response, suffix)
    assert count == 5

@pytest.mark.asyncio
async def test_count_breaches_not_found(checker):
    """Test parsing when hash is not in response"""
    mock_response = "OTHERHASH:10"
    suffix = "C6008F9CAB4083784CBD1874F76618D2A97"
    
    count = checker._count_breaches(mock_response, suffix)
    assert count == 0

@pytest.mark.asyncio
async def test_check_password_breached(checker):
    """Test full check flow for a breached password"""
    pwd = "password123"
    prefix = "CBFDA"
    suffix = "C6008F9CAB4083784CBD1874F76618D2A97"
    
    with aioresponses() as m:
        # Mock the API call
        # Note: aioresponses matches the exact URL string
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
    # We don't know the exact hash here easily without calculating, 
    # but we can trust the checker to generate consistent ones.
    # We just need to mock whatever prefix it requests.
    
    # Let's inspect what the checker generates inside the test
    # by using a side_effect or just trusting the prefix logic we tested in test_hash_password
    # Actually, we can just call the helper:
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
