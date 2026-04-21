"""Threat scoring engine."""
import logging
import uuid
from datetime import datetime, timezone

from src.models.enums import RiskLevel, ScanType
from src.models.responses import (
    ContentAnalysis,
    HeaderAnalysis,
    LinkAnalysis,
    ThreatAssessment,
    ThreatSignal,
)

logger = logging.getLogger(__name__)


class ThreatScoringEngine:
    """Computes unified threat scores from multiple signals."""

    # Scoring weights for email analysis
    EMAIL_WEIGHTS = {
        "header_auth": 0.20,
        "nlp_content": 0.30,
        "link_analysis": 0.25,
        "sender_reputation": 0.15,
        "structural_anomaly": 0.10,
    }

    def compute_email_threat_score(
        self,
        header_analysis: HeaderAnalysis,
        content_analysis: ContentAnalysis,
        link_analysis: LinkAnalysis,
    ) -> ThreatAssessment:
        """Compute comprehensive threat score for email."""

        signals = []

        # Header authentication signal
        header_score = (1 - header_analysis.auth_score) * 100
        signals.append(ThreatSignal(
            name="Email Authentication",
            score=header_score,
            weight=self.EMAIL_WEIGHTS["header_auth"],
            description=f"SPF: {header_analysis.spf_result}, DKIM: {header_analysis.dkim_result}, DMARC: {header_analysis.dmarc_result}"
        ))

        # NLP content signal - composite of multiple factors
        nlp_score = (
            content_analysis.urgency_score * 0.2 +
            content_analysis.authority_impersonation * 0.25 +
            content_analysis.action_pressure * 0.2 +
            content_analysis.threat_language * 0.15 +
            content_analysis.personal_info_request * 0.2
        ) * 100

        signals.append(ThreatSignal(
            name="Content Analysis",
            score=nlp_score,
            weight=self.EMAIL_WEIGHTS["nlp_content"],
            description=f"Social engineering tactics: {', '.join(content_analysis.social_engineering_tactics) or 'None detected'}"
        ))

        # Link analysis signal
        link_score = 0
        if link_analysis.urls_found:
            suspicious_ratio = len(link_analysis.suspicious_urls) / len(link_analysis.urls_found)
            link_score = suspicious_ratio * 100

        signals.append(ThreatSignal(
            name="Link Analysis",
            score=link_score,
            weight=self.EMAIL_WEIGHTS["link_analysis"],
            description=f"{len(link_analysis.suspicious_urls)} suspicious URLs found"
        ))

        # Sender reputation (simplified)
        sender_score = 0
        if header_analysis.reply_to_mismatch:
            sender_score += 50
        if not header_analysis.return_path_match:
            sender_score += 30

        signals.append(ThreatSignal(
            name="Sender Reputation",
            score=sender_score,
            weight=self.EMAIL_WEIGHTS["sender_reputation"],
            description="Based on reply-to and return-path analysis"
        ))

        # Calculate overall score
        overall_score = sum(
            signal.score * signal.weight for signal in signals
        )

        # Determine risk level
        risk_level = self._score_to_risk_level(overall_score)

        # Generate recommendations
        recommendations = self._generate_recommendations(
            risk_level,
            header_analysis,
            content_analysis,
            link_analysis
        )

        # Extract IOCs
        iocs = self._extract_iocs(link_analysis)

        return ThreatAssessment(
            scan_id=str(uuid.uuid4()),
            scan_type=ScanType.EMAIL,
            timestamp=datetime.now(timezone.utc),
            overall_score=int(overall_score),
            risk_level=risk_level,
            confidence=0.85,
            signals=signals,
            iocs=iocs,
            recommendations=recommendations,
            raw_analysis={
                "header_analysis": header_analysis.model_dump(),
                "content_analysis": content_analysis.model_dump(),
                "link_analysis": link_analysis.model_dump(),
            }
        )

    def compute_url_threat_score(self, url_analysis: dict) -> ThreatAssessment:
        """Compute threat score for URL analysis."""

        signals = []

        # Domain reputation signal
        domain_score = url_analysis["risk_score"] * 100

        signals.append(ThreatSignal(
            name="Domain Analysis",
            score=domain_score,
            weight=1.0,
            description=f"Domain: {url_analysis['domain']}"
        ))

        overall_score = domain_score
        risk_level = self._score_to_risk_level(overall_score)

        # Generate recommendations
        recommendations = []
        if url_analysis["typosquat_target"]:
            recommendations.append(
                f"Possible typosquatting of {url_analysis['typosquat_target']}"
            )
        if url_analysis["is_newly_registered"]:
            recommendations.append("Domain registered within last 30 days")
        if url_analysis["has_ip_address"]:
            recommendations.append("URL uses IP address instead of domain name")

        if risk_level in [RiskLevel.PHISHING, RiskLevel.LIKELY_PHISHING]:
            recommendations.append("Do not click this link")
            recommendations.append("Report to security team")

        return ThreatAssessment(
            scan_id=str(uuid.uuid4()),
            scan_type=ScanType.URL,
            timestamp=datetime.now(timezone.utc),
            overall_score=int(overall_score),
            risk_level=risk_level,
            confidence=0.80,
            signals=signals,
            iocs=[url_analysis["url"]],
            recommendations=recommendations,
            raw_analysis=url_analysis
        )

    def _score_to_risk_level(self, score: float) -> RiskLevel:
        """Convert numeric score to risk level."""
        if score >= 80:
            return RiskLevel.PHISHING
        elif score >= 60:
            return RiskLevel.LIKELY_PHISHING
        elif score >= 40:
            return RiskLevel.SUSPICIOUS
        else:
            return RiskLevel.SAFE

    def _generate_recommendations(
        self,
        risk_level: RiskLevel,
        header_analysis: HeaderAnalysis,
        content_analysis: ContentAnalysis,
        link_analysis: LinkAnalysis,
    ) -> list[str]:
        """Generate actionable recommendations."""
        recommendations = []

        if risk_level in [RiskLevel.PHISHING, RiskLevel.LIKELY_PHISHING]:
            recommendations.append("Do not click any links in this email")
            recommendations.append("Do not reply or provide any information")
            recommendations.append("Report to security team immediately")
            recommendations.append("Delete this email")

        if header_analysis.auth_score < 0.5:
            recommendations.append("Email failed authentication checks")

        if content_analysis.personal_info_request > 0.7:
            recommendations.append("Email requests sensitive information - likely phishing")

        if link_analysis.shortened_urls:
            recommendations.append("Email contains URL shorteners - verify destination")

        if content_analysis.ai_generated_probability > 0.7:
            recommendations.append("Content appears to be AI-generated")

        return recommendations

    def _extract_iocs(self, link_analysis: LinkAnalysis) -> list[str]:
        """Extract Indicators of Compromise."""
        iocs = []

        for url_info in link_analysis.suspicious_urls:
            iocs.append(url_info["url"])

        return iocs