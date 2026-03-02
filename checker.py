import asyncio
import hashlib
import logging
import re
import sys
import time
from typing import List, Optional, Dict, Any
from urllib.parse import urljoin

import aiohttp
import colorama
from colorama import Fore, Style
from tqdm.asyncio import tqdm

from models import PasswordAnalysis, SecurityLevel

class PasswordSecurityError(Exception):
    """Custom exception for password security operations"""
    pass

class PasswordChecker:
    """
    Advanced password security checker with breach detection and strength analysis
    """
    HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
    REQUEST_TIMEOUT = 10
    MAX_RETRIES = 3
    RATE_LIMIT_DELAY = 0.1  # 100ms between requests

    def __init__(self, 
                 timeout: int = REQUEST_TIMEOUT,
                 max_retries: int = MAX_RETRIES,
                 enable_logging: bool = True):
        self.timeout = timeout
        self.max_retries = max_retries
        self.session: Optional[aiohttp.ClientSession] = None
        if enable_logging:
            self._setup_logging()
        else:
            self.logger = logging.getLogger(__name__)
            self.logger.addHandler(logging.NullHandler())
        colorama.init(autoreset=True)

    def _setup_logging(self) -> None:
        log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        from pathlib import Path
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler(Path('password_checker.log')),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers={'Add-Padding': 'true', 'User-Agent': 'AdvancedPasswordChecker/1.0'}
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def _hash_password(self, password: str) -> tuple[str, str]:
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        return sha1_hash[:5], sha1_hash[5:]

    async def _fetch_breach_data(self, prefix: str) -> str:
        if not self.session:
            raise PasswordSecurityError("Session not initialized. Use async context manager.")
        url = urljoin(self.HIBP_API_URL, prefix)
        for attempt in range(self.max_retries):
            try:
                async with self.session.get(url) as response:
                    if response.status == 200:
                        return await response.text()
                    elif response.status == 404:
                        return ""  # No breaches found
                    elif response.status == 429:
                        delay = (2 ** attempt) * self.RATE_LIMIT_DELAY
                        await asyncio.sleep(delay)
                        continue
                    else:
                        raise PasswordSecurityError(
                            f"API returned status {response.status}: {await response.text()}"
                        )
            except asyncio.TimeoutError:
                if attempt == self.max_retries - 1:
                    raise PasswordSecurityError(f"Request timeout after {self.max_retries} attempts")
                await asyncio.sleep(1)
            except Exception as e:
                if attempt == self.max_retries - 1:
                    raise PasswordSecurityError(f"Request failed: {str(e)}")
                await asyncio.sleep(1)
        raise PasswordSecurityError("Max retries exceeded")

    def _count_breaches(self, response_text: str, suffix: str) -> int:
        for line in response_text.splitlines():
            if ':' in line:
                hash_suffix, count_str = line.split(':', 1)
                if hash_suffix.strip().upper() == suffix.upper():
                    return int(count_str.strip())
        return 0

    def _analyze_password_strength(self, password: str) -> Dict[str, Any]:
        checks = {
            'length': len(password) >= 12,
            'lowercase': bool(re.search(r'[a-z]', password)),
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'digits': bool(re.search(r'\d', password)),
            'special_chars': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
            'no_common_patterns': not bool(re.search(r'(123|abc|qwe|password|admin)', password.lower())),
            'no_repetition': not bool(re.search(r'(.)\1{2,}', password)),
            'no_sequential': not any(
                password.lower()[i:i+3] in 'abcdefghijklmnopqrstuvwxyz0123456789'
                for i in range(len(password) - 2)
            )
        }
        score = sum(checks.values())
        max_score = len(checks)
        strength_percentage = (score / max_score) * 100
        feedback = []
        if not checks['length']:
            feedback.append("Use at least 12 characters")
        if not checks['lowercase']:
            feedback.append("Include lowercase letters")
        if not checks['uppercase']:
            feedback.append("Include uppercase letters")
        if not checks['digits']:
            feedback.append("Include numbers")
        if not checks['special_chars']:
            feedback.append("Include special characters")
        if not checks['no_common_patterns']:
            feedback.append("Avoid common patterns (123, abc, password, etc.)")
        if not checks['no_repetition']:
            feedback.append("Avoid repeated characters")
        if not checks['no_sequential']:
            feedback.append("Avoid sequential characters")
        if strength_percentage >= 90:
            level = SecurityLevel.EXCELLENT
        elif strength_percentage >= 75:
            level = SecurityLevel.STRONG
        elif strength_percentage >= 60:
            level = SecurityLevel.MODERATE
        elif strength_percentage >= 40:
            level = SecurityLevel.WEAK
        else:
            level = SecurityLevel.CRITICAL
        return {
            'score': score,
            'max_score': max_score,
            'percentage': strength_percentage,
            'level': level,
            'checks': checks,
            'feedback': feedback
        }

    async def check_password(self, password: str) -> PasswordAnalysis:
        start_time = time.time()
        prefix, suffix = self._hash_password(password)
        try:
            response_text = await self._fetch_breach_data(prefix)
            breach_count = self._count_breaches(response_text, suffix)
        except PasswordSecurityError as e:
            self.logger.error(f"Breach check failed: {e}")
            breach_count = -1
        strength_analysis = self._analyze_password_strength(password)
        security_level = strength_analysis['level']
        if breach_count > 0:
            security_level = SecurityLevel.CRITICAL
        elif breach_count == -1:
            pass
        response_time = time.time() - start_time
        return PasswordAnalysis(
            password_hash=f"{prefix}{'*' * len(suffix)}",
            breach_count=breach_count,
            security_level=security_level,
            strength_score=strength_analysis['score'],
            feedback=strength_analysis['feedback'],
            local_checks=strength_analysis['checks'],
            response_time=response_time
        )

    async def check_passwords_batch(self, passwords: List[str]) -> List[PasswordAnalysis]:
        results = []
        semaphore = asyncio.Semaphore(5)
        async def check_with_semaphore(password: str) -> PasswordAnalysis:
            async with semaphore:
                result = await self.check_password(password)
                await asyncio.sleep(self.RATE_LIMIT_DELAY)
                return result
        tasks = [check_with_semaphore(pwd) for pwd in passwords]
        results = await tqdm.gather(*tasks, desc="Checking passwords", unit="pwd")
        return results

    def format_result(self, analysis: PasswordAnalysis, show_details: bool = True) -> str:
        color_map = {
            SecurityLevel.CRITICAL: Fore.RED,
            SecurityLevel.WEAK: Fore.YELLOW,
            SecurityLevel.MODERATE: Fore.CYAN,
            SecurityLevel.STRONG: Fore.GREEN,
            SecurityLevel.EXCELLENT: Fore.MAGENTA
        }
        color = color_map.get(analysis.security_level, Fore.WHITE)
        result = f"{color}Security Level: {analysis.security_level.value}{Style.RESET_ALL}\n"
        if analysis.breach_count > 0:
            result += f"{Fore.RED}⚠️  Found in {analysis.breach_count:,} data breaches - CHANGE IMMEDIATELY!{Style.RESET_ALL}\n"
        elif analysis.breach_count == 0:
            result += f"{Fore.GREEN}✓ Not found in known data breaches{Style.RESET_ALL}\n"
        else:
            result += f"{Fore.YELLOW}? Could not check breach database{Style.RESET_ALL}\n"
        result += f"Strength Score: {analysis.strength_score}/{len(analysis.local_checks)} "
        result += f"({(analysis.strength_score/len(analysis.local_checks)*100):.0f}%)\n"
        if show_details and analysis.feedback:
            result += f"\n{Fore.CYAN}Recommendations:{Style.RESET_ALL}\n"
            for feedback in analysis.feedback:
                result += f"  • {feedback}\n"
        result += f"Response Time: {analysis.response_time:.2f}s\n"
        return result
