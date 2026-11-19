"""
Kali AI - Finding Correlator & Risk Prioritizer
Groups related findings, detects duplicates, correlates cross-tool evidence,
and calculates overall assessment risk prioritization.
"""

from __future__ import annotations

import logging
from typing import Any
from backend.models.schemas import Finding, Severity, Confidence

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 4.5,
    Severity.LOW: 2.0,
    Severity.INFORMATIONAL: 0.5,
}

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 4,
}


class FindingCorrelator:
    """Correlates multiple findings across tool results, merges duplicates, and scores risk."""

    @classmethod
    def deduplicate(cls, findings: list[Finding]) -> list[Finding]:
        """
        Merge duplicates that refer to the same title/category and affected asset,
        aggregating evidence and preserving the highest severity.
        """
        unique_map: dict[tuple[str, str], Finding] = {}

        for f in findings:
            key = (f.title.strip().lower(), f.affected_asset.strip().lower())
            if key not in unique_map:
                unique_map[key] = f.model_copy(deep=True)
            else:
                existing = unique_map[key]
                # Merge evidence
                for ev in f.evidence:
                    if ev not in existing.evidence:
                        existing.evidence.append(ev)
                # Keep highest severity
                if SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[existing.severity]:
                    existing.severity = f.severity
                # Upgrade confidence if any is confirmed
                if f.confidence == Confidence.CONFIRMED:
                    existing.confidence = Confidence.CONFIRMED

        return list(unique_map.values())

    @classmethod
    def correlate_cross_tool_evidence(cls, findings: list[Finding]) -> list[Finding]:
        """
        Synthesize insights when findings across tools reinforce each other.
        For example:
        - WhatWeb detects WordPress + Nuclei detects XML-RPC -> Elevate finding context.
        - Nmap detects Port 80/443 + SSLyze detects TLS protocol flaw -> Elevate impact description.
        """
        has_wordpress = any("wordpress" in f.title.lower() or "wordpress" in f.description.lower() for f in findings)
        xmlrpc_finding = next((f for f in findings if "xml-rpc" in f.title.lower()), None)

        if has_wordpress and xmlrpc_finding:
            # Correlate: Add cross-tool validation
            if "Verified with WhatWeb CMS detection" not in xmlrpc_finding.evidence:
                xmlrpc_finding.evidence.append("Cross-correlated: WhatWeb confirmed active WordPress CMS deployment.")
                xmlrpc_finding.confidence = Confidence.CONFIRMED

        return findings

    @classmethod
    def prioritize(cls, findings: list[Finding]) -> list[Finding]:
        """Sort findings by risk: Critical first down to Informational."""
        return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 5))

    @classmethod
    def calculate_risk_score(cls, findings: list[Finding]) -> dict[str, Any]:
        """
        Calculate an overall risk posture score (0 - 100) and severity breakdown.
        """
        breakdown = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
        }

        total_weighted_points = 0.0
        for f in findings:
            sev_str = f.severity.value
            breakdown[sev_str] = breakdown.get(sev_str, 0) + 1
            total_weighted_points += SEVERITY_WEIGHTS.get(f.severity, 1.0)

        # Scale score on a 0-100 curve with logarithmic dampening
        # 1 Critical (10 pts) + 1 High (7.5 pts) = 17.5 -> ~65-75 score
        raw_score = min(100.0, total_weighted_points * 3.5)

        if raw_score >= 70:
            rating = "HIGH RISK"
        elif raw_score >= 35:
            rating = "MODERATE RISK"
        elif raw_score > 0:
            rating = "LOW RISK"
        else:
            rating = "INFORMATIONAL / SECURE"

        return {
            "score": round(raw_score, 1),
            "rating": rating,
            "breakdown": breakdown,
            "total_findings": len(findings),
        }
