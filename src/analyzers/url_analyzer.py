"""URL and domain analysis module."""
import logging
import re
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

import whois

logger = logging.getLogger(__name__)


class URLAnalyzer:
    """Analyzes URLs for phishing indicators."""

    # Legitimate domains to check for typosquatting
    LEGITIMATE_DOMAINS = [
        "google.com", "microsoft.com", "apple.com", "amazon.com",
        "facebook.com", "paypal.com", "netflix.com", "linkedin.com",
        "dropbox.com", "chase.com", "wellsfargo.com", "bankofamerica.com",
        "dhl.com", "fedex.com", "ups.com", "usps.com",
        "docusign.com", "adobe.com", "zoom.us", "slack.com",
    ]

    SUSPICIOUS_TLDS = [
        ".xyz", ".top", ".buzz", ".click", ".loan", ".download",
        ".stream", ".gq", ".ml", ".cf", ".tk"
    ]

    def __init__(self):
        """Initialize URL analyzer."""
        pass

    async def analyze_url(self, url: str) -> dict:
        """Perform comprehensive URL analysis."""
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]

        analysis = {
            "url": url,
            "domain": domain,
            "has_ip_address": self._has_ip_address(url),
            "suspicious_tld": self._has_suspicious_tld(domain),
            "excessive_subdomains": self._has_excessive_subdomains(domain),
            "typosquat_target": self._detect_typosquat(domain),
            "domain_age_days": await self._get_domain_age(domain),
            "is_newly_registered": False,
            "homoglyph_detected": self._detect_homoglyphs(domain),
            "url_length_anomaly": len(url) > 150,
            "encoded_characters": '%' in url,
            "risk_score": 0.0
        }

        # Calculate risk score
        risk_score = 0.0

        if analysis["has_ip_address"]:
            risk_score += 0.8
        if analysis["suspicious_tld"]:
            risk_score += 0.5
        if analysis["excessive_subdomains"]:
            risk_score += 0.4
        if analysis["typosquat_target"]:
            risk_score += 0.9
        if analysis["homoglyph_detected"]:
            risk_score += 0.7
        if analysis["domain_age_days"] is not None and analysis["domain_age_days"] < 30:
            risk_score += 0.7
            analysis["is_newly_registered"] = True

        analysis["risk_score"] = min(1.0, risk_score)

        return analysis

    def _has_ip_address(self, url: str) -> bool:
        """Check if URL uses IP address instead of domain."""
        ip_pattern = r'https?://\d+\.\d+\.\d+\.\d+'
        return bool(re.search(ip_pattern, url))

    def _has_suspicious_tld(self, domain: str) -> bool:
        """Check if domain uses a suspicious TLD."""
        domain_lower = domain.lower()
        return any(tld in domain_lower for tld in self.SUSPICIOUS_TLDS)

    def _has_excessive_subdomains(self, domain: str) -> bool:
        """Check for excessive number of subdomains."""
        parts = domain.split('.')
        return len(parts) > 4

    def _detect_typosquat(self, domain: str) -> str | None:
        """Detect potential typosquatting of legitimate domains."""
        domain_lower = domain.lower()

        for legit_domain in self.LEGITIMATE_DOMAINS:
            # Check for exact substring match
            if legit_domain.replace('.com', '') in domain_lower:
                if domain_lower != legit_domain:
                    return legit_domain

            # Check Levenshtein distance (simple version)
            if self._levenshtein_distance(domain_lower, legit_domain) <= 2:
                return legit_domain

        return None

    def _detect_homoglyphs(self, domain: str) -> bool:
        """Detect homoglyph characters (lookalike characters)."""
        # Common homoglyphs
        homoglyphs = {
            'а': 'a',  # Cyrillic 'a'
            'е': 'e',  # Cyrillic 'e'
            'о': 'o',  # Cyrillic 'o'
            'р': 'p',  # Cyrillic 'p'
            'с': 'c',  # Cyrillic 'c'
            'у': 'y',  # Cyrillic 'y'
            'х': 'x',  # Cyrillic 'x'
        }

        for char in domain:
            if char in homoglyphs:
                return True

        return False

    async def _get_domain_age(self, domain: str) -> int | None:
        """Get domain age in days."""
        try:
            # Remove port if present
            domain = domain.split(':')[0]

            # Try to get WHOIS info
            w = whois.whois(domain)

            if w.creation_date:
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]

                if creation_date:
                    age = (datetime.now(timezone.utc) - creation_date.replace(tzinfo=timezone.utc)).days
                    return age

        except Exception as e:
            logger.debug(f"Could not retrieve domain age for {domain}: {e}")

        return None

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]