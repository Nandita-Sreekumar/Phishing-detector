"""Email analysis module."""
import logging
import re
from typing import Any

from src.models.responses import HeaderAnalysis, LinkAnalysis
from src.utils.email_parsers import extract_urls, parse_raw_email

logger = logging.getLogger(__name__)


class EmailAnalyzer:
    """Analyzes emails for phishing indicators."""

    def __init__(self):
        """Initialize email analyzer."""
        self.shortener_domains = [
            "bit.ly", "tinyurl.com", "goo.gl", "ow.ly",
            "t.co", "buff.ly", "is.gd", "cli.gs"
        ]

    async def analyze_headers(self, headers: dict[str, str]) -> HeaderAnalysis:
        """Analyze email headers for authentication and anomalies."""
        auth_score = 1.0

        # Check SPF
        spf_result = self._extract_auth_result(headers, "spf")
        if spf_result in ["fail", "softfail"]:
            auth_score -= 0.3

        # Check DKIM
        dkim_result = self._extract_auth_result(headers, "dkim")
        if dkim_result == "fail":
            auth_score -= 0.3

        # Check DMARC
        dmarc_result = self._extract_auth_result(headers, "dmarc")
        if dmarc_result == "fail":
            auth_score -= 0.2

        # Check Return-Path vs From
        from_addr = headers.get("From", "").lower()
        return_path = headers.get("Return-Path", "").lower()
        return_path_match = self._domains_match(from_addr, return_path)
        if not return_path_match:
            auth_score -= 0.1

        # Check Reply-To mismatch
        reply_to = headers.get("Reply-To", "").lower()
        reply_to_mismatch = False
        if reply_to and not self._domains_match(from_addr, reply_to):
            reply_to_mismatch = True
            auth_score -= 0.1

        auth_score = max(0.0, min(1.0, auth_score))

        return HeaderAnalysis(
            spf_result=spf_result,
            dkim_result=dkim_result,
            dmarc_result=dmarc_result,
            return_path_match=return_path_match,
            reply_to_mismatch=reply_to_mismatch,
            received_chain_anomaly=False,  # Simplified for now
            x_originating_ip=headers.get("X-Originating-IP"),
            auth_score=auth_score
        )

    async def analyze_links(
        self,
        email_body: str,
        html_content: str | None = None
    ) -> LinkAnalysis:
        """Analyze links in email for suspicious patterns."""
        urls = extract_urls(email_body)
        if html_content:
            urls.extend(extract_urls(html_content))

        urls = list(set(urls))  # Remove duplicates

        suspicious_urls = []
        shortened_urls = []
        data_uri_present = "data:" in email_body

        for url in urls:
            # Check for URL shorteners
            if any(domain in url for domain in self.shortener_domains):
                shortened_urls.append(url)
                suspicious_urls.append({
                    "url": url,
                    "reason": "URL shortener detected",
                    "risk_score": 0.6
                })

            # Check for IP addresses in URL
            if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
                suspicious_urls.append({
                    "url": url,
                    "reason": "IP address instead of domain",
                    "risk_score": 0.8
                })

            # Check for suspicious TLDs
            suspicious_tlds = ['.xyz', '.top', '.buzz', '.click', '.loan']
            if any(tld in url.lower() for tld in suspicious_tlds):
                suspicious_urls.append({
                    "url": url,
                    "reason": "Suspicious TLD",
                    "risk_score": 0.5
                })

        return LinkAnalysis(
            urls_found=urls,
            suspicious_urls=suspicious_urls,
            url_to_text_mismatch=False,  # Would need HTML parsing
            shortened_urls=shortened_urls,
            data_uri_present=data_uri_present
        )

    def _extract_auth_result(
        self,
        headers: dict[str, str],
        auth_type: str
    ) -> str | None:
        """Extract authentication result from headers."""
        auth_results = headers.get("Authentication-Results", "").lower()

        if not auth_results:
            return "none"

        if f"{auth_type}=pass" in auth_results:
            return "pass"
        elif f"{auth_type}=fail" in auth_results:
            return "fail"
        elif f"{auth_type}=softfail" in auth_results:
            return "softfail"

        return "none"

    def _domains_match(self, email1: str, email2: str) -> bool:
        """Check if two email addresses have matching domains."""
        if not email1 or not email2:
            return True

        domain1 = email1.split('@')[-1] if '@' in email1 else email1
        domain2 = email2.split('@')[-1] if '@' in email2 else email2

        # Remove brackets and whitespace
        domain1 = domain1.strip('<> \\t\\n\\r')
        domain2 = domain2.strip('<> \\t\\n\\r')

        return domain1 == domain2