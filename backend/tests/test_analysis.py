"""
Unit tests for Finding Normalization, Correlation, and Risk Scoring.
"""

from backend.models.schemas import Severity, Confidence, Finding
from backend.services.analysis.normalizer import FindingNormalizer
from backend.services.analysis.correlator import FindingCorrelator


def test_normalize_nmap_output():
    raw_output = {
        "tool": "nmap",
        "target": "127.0.0.1",
        "ports": [
            {"port": 22, "state": "open", "service": "ssh", "version": "OpenSSH 8.9"},
            {"port": 80, "state": "open", "service": "http", "version": "nginx 1.24"},
            {"port": 3306, "state": "open", "service": "mysql", "version": "8.0"},
        ],
    }
    findings = FindingNormalizer.normalize("nmap_scan", raw_output, "127.0.0.1")
    assert len(findings) == 3

    # Check sensitive database port detection
    mysql_f = next((f for f in findings if "3306" in f.affected_asset), None)
    assert mysql_f is not None
    assert mysql_f.severity == Severity.MEDIUM
    assert "MySQL" in mysql_f.title


def test_normalize_whatweb_output():
    raw_output = {
        "tool": "whatweb",
        "target": "localhost",
        "technologies": [
            {"name": "WordPress", "version": "6.4.2", "category": "CMS"},
        ],
        "headers": {
            "Server": "nginx/1.24.0",
            "X-Powered-By": "PHP/8.2",
        },
    }
    findings = FindingNormalizer.normalize("whatweb_scan", raw_output, "localhost")
    assert len(findings) >= 3

    server_hdr = next((f for f in findings if "Server Banner" in f.title), None)
    assert server_hdr is not None
    assert server_hdr.severity == Severity.LOW

    cms = next((f for f in findings if "CMS Detected" in f.title), None)
    assert cms is not None
    assert "WordPress" in cms.description


def test_normalize_nuclei_output():
    raw_output = {
        "tool": "nuclei",
        "target": "localhost",
        "vulnerabilities": [
            {
                "template_id": "cve-2023-1234",
                "name": "Critical Remote Code Execution",
                "severity": "critical",
                "matched_at": "http://localhost/vuln",
                "description": "High impact RCE vulnerability.",
            }
        ],
    }
    findings = FindingNormalizer.normalize("nuclei_scan", raw_output, "localhost")
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].confidence == Confidence.CONFIRMED


def test_finding_correlator_deduplication():
    f1 = Finding(
        title="Open Port: 80/tcp",
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.POTENTIAL,
        category="Port Discovery",
        affected_asset="127.0.0.1:80",
        description="Port is listening",
        evidence=["Probe 1"],
    )
    f2 = Finding(
        title="Open Port: 80/tcp",
        severity=Severity.LOW,
        confidence=Confidence.CONFIRMED,
        category="Port Discovery",
        affected_asset="127.0.0.1:80",
        description="Port is listening verified",
        evidence=["Probe 2"],
    )

    deduped = FindingCorrelator.deduplicate([f1, f2])
    assert len(deduped) == 1
    assert "Probe 1" in deduped[0].evidence
    assert "Probe 2" in deduped[0].evidence
    assert deduped[0].severity == Severity.LOW
    assert deduped[0].confidence == Confidence.CONFIRMED


def test_finding_correlator_prioritization():
    f_info = Finding(title="Info", severity=Severity.INFORMATIONAL, confidence=Confidence.CONFIRMED, category="", affected_asset="", description="")
    f_crit = Finding(title="Crit", severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED, category="", affected_asset="", description="")
    f_med = Finding(title="Med", severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED, category="", affected_asset="", description="")

    prioritized = FindingCorrelator.prioritize([f_info, f_crit, f_med])
    assert prioritized[0].severity == Severity.CRITICAL
    assert prioritized[1].severity == Severity.MEDIUM
    assert prioritized[2].severity == Severity.INFORMATIONAL


def test_risk_score_calculation():
    findings = [
        Finding(title="Crit Vuln", severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED, category="", affected_asset="", description=""),
        Finding(title="Med Vuln", severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED, category="", affected_asset="", description=""),
    ]
    score_data = FindingCorrelator.calculate_risk_score(findings)
    assert score_data["score"] > 0
    assert score_data["breakdown"]["critical"] == 1
    assert score_data["breakdown"]["medium"] == 1
    assert score_data["total_findings"] == 2
