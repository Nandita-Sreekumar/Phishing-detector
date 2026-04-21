from enum import Enum


class RiskLevel(str, Enum):
    """Risk level classifications."""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    LIKELY_PHISHING = "likely_phishing"
    PHISHING = "phishing"


class ScanType(str, Enum):
    """Types of scans supported."""
    EMAIL = "email"
    URL = "url"
    IMAGE = "image"


class PatchUrgency(str, Enum):
    """Patch urgency levels."""
    IMMEDIATE = "immediate"
    SOON = "soon"
    PLANNED = "planned"
    MONITOR = "monitor"