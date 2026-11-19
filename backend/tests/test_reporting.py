"""
Unit tests for the Security Report Generator.
"""

from backend.models.schemas import Assessment, AssessmentPlan, AssessmentStatus, Finding, Severity, Confidence
from backend.services.reporting.generator import ReportGenerator


def test_markdown_report_generation():
    assessment = Assessment(
        objective="Assess authorized web server",
        status=AssessmentStatus.COMPLETED,
        plan=AssessmentPlan(
            objective="Assess authorized web server",
            steps=["Identify technologies", "Scan ports", "Vulnerability check"],
            scope="127.0.0.1",
        ),
        findings=[
            Finding(
                title="Exposed Database Service (MySQL)",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category="Network Service Exposure",
                affected_asset="127.0.0.1:3306",
                description="Database port is open externally.",
                evidence=["Port 3306 open"],
                remediation="Firewall access to private IPs only.",
                source_tool="nmap_scan",
            )
        ],
        demo_mode=True,
    )

    report = ReportGenerator.generate_markdown(assessment)
    assert "# KALI AI - CYBERSECURITY ASSESSMENT REPORT" in report
    assert "Executive Summary" in report
    assert "Exposed Database Service (MySQL)" in report
    assert "127.0.0.1:3306" in report
    assert "Firewall access to private IPs only." in report
    assert "Remediation Roadmap" in report
