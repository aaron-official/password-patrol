from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict

class SecurityLevel(Enum):
    """Password security levels"""
    CRITICAL = "CRITICAL"
    WEAK = "WEAK"
    MODERATE = "MODERATE"
    STRONG = "STRONG"
    EXCELLENT = "EXCELLENT"

@dataclass
class PasswordAnalysis:
    """Comprehensive password analysis results"""
    password_hash: str
    breach_count: int
    security_level: SecurityLevel
    strength_score: int
    feedback: List[str] = field(default_factory=list)
    local_checks: Dict[str, bool] = field(default_factory=dict)
    response_time: float = 0.0
