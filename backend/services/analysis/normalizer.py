"""
Kali AI - Finding Normalizer
Parses and normalizes raw tool output from any registered security tool
into structured, uniform Finding objects.
"""

from __future__ import annotations

import logging
from typing import Any
from backend.models.schemas import Finding, Severity, Confidence

logger = logging.getLogger(__name__)


class FindingNormalizer:
    """Normalizes heterogeneous tool outputs into standardized Finding models."""

    @classmethod
    def normalize(cls, tool_id: str, output: dict[str, Any], target: str = "") -> list[Finding]:
        """Convert a tool's output dictionary into a list of standardized Finding instances."""
        if not output:
            return []

        handler = getattr(cls, f"_normalize_{tool_id}", None)
        if handler:
            try:
                return handler(output, target)
            except Exception as e:
                logger.error("Error normalizing output for %s: %s", tool_id, e)
                return []
        
        logger.debug("No custom normalizer for tool %s, returning generic finding if error present", tool_id)
        return []

    # ──────────────────────────────────────────────
    # 1. Nmap Normalization
    # ──────────────────────────────────────────────
    @classmethod
    def _normalize_nmap_scan(cls, output: dict[str, Any], target: str) -> list[Finding]:
        findings: list[Finding] = []
        host = output.get("target", target)
        ports = output.get("ports", [])

        sensitive_ports = {
            21: ("FTP Service Exposed", Severity.MEDIUM, "FTP service allows unencrypted or legacy file transfers."),
            22: ("SSH Service Exposed", Severity.INFORMATIONAL, "Remote administrative SSH service detected."),
            23: ("Telnet Service Exposed", Severity.HIGH, "Telnet sends plaintext credentials across the network."),
            135: ("Microsoft RPC Endpoint Mapper Exposed", Severity.LOW, "MSRPC endpoint mapper service is accessible. Should be firewalled from untrusted networks."),
            139: ("NetBIOS Session Service Exposed", Severity.MEDIUM, "NetBIOS session service exposed; risk of legacy network enumeration."),
            445: ("Microsoft SMB File Sharing Service Exposed", Severity.MEDIUM, "SMB file sharing service is active; ensure SMB signing is enforced and access is restricted."),
            1433: ("Microsoft SQL Server Database Exposed", Severity.MEDIUM, "MSSQL database port is exposed to the network."),
            3306: ("MySQL Database Service Exposed", Severity.MEDIUM, "Database server port is exposed; should restrict to private subnet."),
            3389: ("Remote Desktop (RDP) Service Exposed", Severity.MEDIUM, "RDP service detected; ensure NLA is enforced and brute-force protection is active."),
            5432: ("PostgreSQL Database Service Exposed", Severity.MEDIUM, "PostgreSQL service is accessible externally."),
            6379: ("Redis Cache Service Exposed", Severity.HIGH, "Redis instance may lack authentication or bind to public interface."),
            8000: ("Alternative HTTP Web Service Active", Severity.INFORMATIONAL, "Common development or microservice HTTP endpoint is active."),
            8080: ("Alternative HTTP Proxy/Web Service Active", Severity.INFORMATIONAL, "Secondary HTTP service port is listening."),
            27017: ("MongoDB Database Service Exposed", Severity.HIGH, "MongoDB database exposed to the network."),
        }

        for p in ports:
            port_num = p.get("port")
            state = p.get("state")
            service = p.get("service", "")
            version = p.get("version", "")

            if state == "open":
                if port_num in sensitive_ports:
                    title, severity, desc = sensitive_ports[port_num]
                    findings.append(Finding(
                        title=f"{title} (Port {port_num})",
                        severity=severity,
                        confidence=Confidence.CONFIRMED,
                        category="Network Service Exposure",
                        affected_asset=f"{host}:{port_num}",
                        description=f"{desc} Running: {service} {version}".strip(),
                        evidence=[f"Port {port_num}/tcp is {state} ({service} {version})"],
                        impact="Potential unauthorized access or credential brute-forcing if unhardened.",
                        remediation=f"Restrict access to port {port_num} via firewall allowlists or VPN.",
                        source_tool="nmap_scan",
                        verification_status="verified",
                    ))
                else:
                    findings.append(Finding(
                        title=f"Open Port: {port_num}/tcp ({service})",
                        severity=Severity.INFORMATIONAL,
                        confidence=Confidence.CONFIRMED,
                        category="Port Discovery",
                        affected_asset=f"{host}:{port_num}",
                        description=f"Port {port_num} is open running {service} {version}".strip(),
                        evidence=[f"Port {port_num} state={state}, service={service}, version={version}"],
                        impact="Exposes service surface to potential reconnaissance.",
                        remediation="Verify whether this port is required for public operations.",
                        source_tool="nmap_scan",
                        verification_status="verified",
                    ))

        return findings

    # ──────────────────────────────────────────────
    # 2. WhatWeb Normalization
    # ──────────────────────────────────────────────
    @classmethod
    def _normalize_whatweb_scan(cls, output: dict[str, Any], target: str) -> list[Finding]:
        findings: list[Finding] = []
        host = output.get("target", target)
        technologies = output.get("technologies", [])
        headers = output.get("headers", {})

        # Header disclosures
        if "Server" in headers:
            findings.append(Finding(
                title=f"Server Banner Information Disclosure ({headers['Server']})",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                category="Information Disclosure",
                affected_asset=host,
                description=f"The web server reveals its software and version in the Server header: {headers['Server']}",
                evidence=[f"Server: {headers['Server']}"],
                impact="Allows targeted exploit selection against specific server software releases.",
                remediation="Configure server tokens to production mode (e.g., server_tokens off in nginx).",
                source_tool="whatweb_scan",
                verification_status="verified",
            ))

        if "X-Powered-By" in headers:
            findings.append(Finding(
                title=f"X-Powered-By Header Information Disclosure ({headers['X-Powered-By']})",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                category="Information Disclosure",
                affected_asset=host,
                description=f"Web framework/runtime disclosed via X-Powered-By: {headers['X-Powered-By']}",
                evidence=[f"X-Powered-By: {headers['X-Powered-By']}"],
                impact="Assists attackers in profiling backend technology stack.",
                remediation="Disable expose_php in php.ini or strip X-Powered-By header via reverse proxy.",
                source_tool="whatweb_scan",
                verification_status="verified",
            ))

        # Technology profile
        cms_list = [t for t in technologies if t.get("category") == "CMS"]
        for cms in cms_list:
            findings.append(Finding(
                title=f"CMS Detected: {cms.get('name')} {cms.get('version', '')}".strip(),
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.CONFIRMED,
                category="Technology Identification",
                affected_asset=host,
                description=f"The target utilizes {cms.get('name')} CMS (version {cms.get('version', 'unspecified')}).",
                evidence=[f"Detected CMS: {cms.get('name')} v{cms.get('version')}"],
                impact="Known CMS vulnerabilities and plugins become focal attack vectors.",
                remediation="Keep CMS core and all active plugins updated to the latest stable versions.",
                source_tool="whatweb_scan",
                verification_status="verified",
            ))

        return findings

    # ──────────────────────────────────────────────
    # 3. Nuclei Normalization
    # ──────────────────────────────────────────────
    @classmethod
    def _normalize_nuclei_scan(cls, output: dict[str, Any], target: str) -> list[Finding]:
        findings: list[Finding] = []
        host = output.get("target", target)
        vulns = output.get("vulnerabilities", [])

        sev_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFORMATIONAL,
            "informational": Severity.INFORMATIONAL,
        }

        for v in vulns:
            raw_sev = str(v.get("severity", "informational")).lower()
            severity = sev_map.get(raw_sev, Severity.MEDIUM)

            findings.append(Finding(
                title=v.get("name", "Vulnerability Detected"),
                severity=severity,
                confidence=Confidence.CONFIRMED,
                category="Vulnerability Detection",
                affected_asset=v.get("matched_at", host),
                description=v.get("description", "Vulnerability detected by Nuclei template engine."),
                evidence=[f"Template: {v.get('template_id', 'unknown')}", f"Matched URI: {v.get('matched_at', host)}"],
                impact="Potential unauthorized access, exploitation or security baseline violation.",
                remediation=f"Review template advisory '{v.get('template_id')}' and apply vendor patch.",
                source_tool="nuclei_scan",
                verification_status="verified",
            ))

        return findings

    # ──────────────────────────────────────────────
    # 4. Nikto Normalization
    # ──────────────────────────────────────────────
    @classmethod
    def _normalize_nikto_scan(cls, output: dict[str, Any], target: str) -> list[Finding]:
        findings: list[Finding] = []
        host = output.get("target", target)
        items = output.get("findings", [])

        for item in items:
            desc = item.get("description", "")
            uri = item.get("uri", "/")
            sev = Severity.MEDIUM if "directory listing" in desc.lower() else Severity.LOW

            findings.append(Finding(
                title=f"Web Misconfiguration: {desc[:60]}",
                severity=sev,
                confidence=Confidence.POTENTIAL,
                category="Web Server Configuration",
                affected_asset=f"{host}{uri}",
                description=desc,
                evidence=[f"URI: {uri}", f"Nikto ID: {item.get('id', 'N/A')}"],
                impact="Information disclosure or unauthorized resource navigation.",
                remediation="Disable directory indexing and restrict access to non-public endpoints.",
                source_tool="nikto_scan",
                verification_status="unverified",
            ))

        return findings

    # ──────────────────────────────────────────────
    # 5. SSLyze Normalization
    # ──────────────────────────────────────────────
    @classmethod
    def _normalize_sslyze_scan(cls, output: dict[str, Any], target: str) -> list[Finding]:
        findings: list[Finding] = []
        host = output.get("target", target)
        protocols = output.get("protocols", {})
        cert = output.get("certificate", {})

        # Check weak protocols
        for proto, status in protocols.items():
            if proto in ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"] and status == "enabled":
                findings.append(Finding(
                    title=f"Insecure TLS Protocol Enabled: {proto}",
                    severity=Severity.HIGH if "SSL" in proto else Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    category="Cryptography & TLS",
                    affected_asset=f"{host}:443",
                    description=f"The server negotiates deprecated cryptographic protocol {proto}.",
                    evidence=[f"Protocol {proto}: {status}"],
                    impact="Susceptible to cryptographic downgrade attacks (e.g. POODLE, BEAST).",
                    remediation=f"Disable {proto} on web servers and load balancers. Restrict to TLS 1.2 and TLS 1.3.",
                    source_tool="sslyze_scan",
                    verification_status="verified",
                ))

        if cert and not cert.get("is_valid", True):
            findings.append(Finding(
                title="TLS Certificate Validation Failure",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category="Cryptography & TLS",
                affected_asset=f"{host}:443",
                description="The server TLS certificate is untrusted, self-signed, or expired.",
                evidence=[f"Subject: {cert.get('subject')}", f"Issuer: {cert.get('issuer')}"],
                impact="Clients cannot establish authentic identity, enabling Man-in-the-Middle (MITM) attacks.",
                remediation="Install a valid certificate signed by a recognized Certificate Authority (CA).",
                source_tool="sslyze_scan",
                verification_status="verified",
            ))

        return findings

    # ──────────────────────────────────────────────
    # 6. OWASP ZAP Normalization
    # ──────────────────────────────────────────────
    @classmethod
    def _normalize_zap_scan(cls, output: dict[str, Any], target: str) -> list[Finding]:
        findings: list[Finding] = []
        host = output.get("target", target)
        alerts = output.get("alerts", [])

        sev_map = {
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "informational": Severity.INFORMATIONAL,
        }

        for alert in alerts:
            raw_risk = str(alert.get("risk", "low")).lower()
            severity = sev_map.get(raw_risk, Severity.LOW)

            findings.append(Finding(
                title=alert.get("name", "Web Application Alert"),
                severity=severity,
                confidence=Confidence.CONFIRMED if alert.get("confidence") == "high" else Confidence.POTENTIAL,
                category="Web Application Weakness",
                affected_asset=alert.get("url", host),
                description=alert.get("description", "Security alert identified during OWASP ZAP analysis."),
                evidence=[f"Alert: {alert.get('name')}", f"URL: {alert.get('url', host)}"],
                impact="Potential client-side security bypass or unauthorized parameter handling.",
                remediation="Apply recommended security header guidelines and OWASP Top 10 defenses.",
                source_tool="zap_scan",
                verification_status="verified",
            ))

        return findings

    # ──────────────────────────────────────────────
    # 7. Gobuster Normalization
    # ──────────────────────────────────────────────
    @classmethod
    def _normalize_gobuster_scan(cls, output: dict[str, Any], target: str) -> list[Finding]:
        findings: list[Finding] = []
        host = output.get("target", target)
        paths = output.get("discovered_paths", [])

        sensitive_routes = ["/admin", "/wp-admin", "/login", "/config", "/.git", "/backup"]

        for item in paths:
            path = item.get("path", "")
            status_code = item.get("status")

            if any(path.startswith(sr) for sr in sensitive_routes):
                findings.append(Finding(
                    title=f"Sensitive Endpoint Discovered: {path}",
                    severity=Severity.MEDIUM if status_code == 200 else Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    category="Administrative Exposure",
                    affected_asset=f"{host}{path}",
                    description=f"Discovered administrative or sensitive path '{path}' returning HTTP status {status_code}.",
                    evidence=[f"Path: {path}", f"HTTP Status: {status_code}", f"Size: {item.get('size')} bytes"],
                    impact="Enables brute force attacks, credential harvesting, or unauthorized panel access.",
                    remediation="Restrict access using IP allowlisting, multi-factor authentication, or remove legacy files.",
                    source_tool="gobuster_scan",
                    verification_status="verified",
                ))

        return findings
