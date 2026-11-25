"""
Kali AI — Intelligent Decision Engine
=======================================
Ported and adapted from HexStrike AI v6.0's IntelligentDecisionEngine.

Provides:
  - TargetProfile: live-built profile of a target as scans complete
  - AttackChain: ordered multi-tool attack plan with probability scoring
  - IntelligentDecisionEngine: selects the best tool chain for a target type
  - TargetType / TechnologyStack enums
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ─── Enums ────────────────────────────────────────────────────────────────────

class TargetType(Enum):
    WEB_APPLICATION = "web_application"
    NETWORK_HOST    = "network_host"
    API_ENDPOINT    = "api_endpoint"
    CLOUD_SERVICE   = "cloud_service"
    BINARY_FILE     = "binary_file"
    DOMAIN          = "domain"
    UNKNOWN         = "unknown"


class TechnologyStack(Enum):
    APACHE    = "apache"
    NGINX     = "nginx"
    IIS       = "iis"
    NODEJS    = "nodejs"
    PHP       = "php"
    PYTHON    = "python"
    JAVA      = "java"
    DOTNET    = "dotnet"
    WORDPRESS = "wordpress"
    DRUPAL    = "drupal"
    JOOMLA    = "joomla"
    REACT     = "react"
    ANGULAR   = "angular"
    VUE       = "vue"
    UNKNOWN   = "unknown"


# ─── Target Profile (built as scans complete) ─────────────────────────────────

@dataclass
class TargetProfile:
    target: str
    target_type: TargetType = TargetType.UNKNOWN
    ip_addresses: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)
    technologies: list[TechnologyStack] = field(default_factory=list)
    cms_type: str | None = None
    cloud_provider: str | None = None
    security_headers: dict[str, str] = field(default_factory=dict)
    ssl_info: dict[str, Any] = field(default_factory=dict)
    subdomains: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    attack_surface_score: float = 0.0
    risk_level: str = "unknown"
    confidence_score: float = 0.0
    # Raw tool outputs accumulated
    tool_outputs: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type.value,
            "ip_addresses": self.ip_addresses,
            "open_ports": self.open_ports,
            "services": self.services,
            "technologies": [t.value for t in self.technologies],
            "cms_type": self.cms_type,
            "attack_surface_score": self.attack_surface_score,
            "risk_level": self.risk_level,
            "subdomains": self.subdomains,
            "endpoints": self.endpoints,
        }

    def update_from_nmap(self, output: str | dict[str, Any]) -> None:
        """Parse nmap output (structured dict from ToolRegistry or raw stdout str) for ports and services."""
        if isinstance(output, dict):
            for p in output.get("ports", []):
                if not isinstance(p, dict):
                    continue
                if p.get("state") in ("open", "filtered", None, ""):
                    try:
                        port = int(p.get("port", 0))
                    except (TypeError, ValueError):
                        continue
                    service = str(p.get("service", "") or "")
                    if port > 0:
                        if port not in self.open_ports:
                            self.open_ports.append(port)
                        if service:
                            self.services[port] = service
            # Fallback to raw_xml/stdout if present
            raw_text = str(output.get("raw_xml") or output.get("stdout") or "")
            if raw_text and not self.open_ports:
                self.update_from_nmap(raw_text)
        elif isinstance(output, str):
            for line in output.splitlines():
                m = re.match(r"(\d+)/tcp\s+open\s+(\S+)", line)
                if m:
                    port = int(m.group(1))
                    service = m.group(2)
                    if port not in self.open_ports:
                        self.open_ports.append(port)
                    self.services[port] = service

        # Detect web ports
        web_ports = {80, 443, 8080, 8443, 8000, 8888, 3000}
        if any(p in web_ports for p in self.open_ports):
            if self.target_type == TargetType.UNKNOWN:
                self.target_type = TargetType.WEB_APPLICATION

    def update_from_whatweb(self, output: str | dict[str, Any]) -> None:
        """Parse WhatWeb output (structured dict from ToolRegistry or raw stdout str) for tech stack."""
        if isinstance(output, dict):
            parts: list[str] = []
            for tech in output.get("technologies", []):
                if isinstance(tech, dict):
                    parts.append(str(tech.get("name", "")))
                else:
                    parts.append(str(tech))
            headers = output.get("headers", {})
            if isinstance(headers, dict):
                parts.extend(f"{k} {v}" for k, v in headers.items())
            if output.get("raw"):
                parts.append(str(output.get("raw")))
            lower = " ".join(parts).lower()
        else:
            lower = str(output).lower()

        if "wordpress" in lower:
            self.cms_type = "wordpress"
            if TechnologyStack.WORDPRESS not in self.technologies:
                self.technologies.append(TechnologyStack.WORDPRESS)
        if "drupal" in lower:
            self.cms_type = "drupal"
            if TechnologyStack.DRUPAL not in self.technologies:
                self.technologies.append(TechnologyStack.DRUPAL)
        if "joomla" in lower:
            self.cms_type = "joomla"
            if TechnologyStack.JOOMLA not in self.technologies:
                self.technologies.append(TechnologyStack.JOOMLA)
        if "php" in lower and TechnologyStack.PHP not in self.technologies:
            self.technologies.append(TechnologyStack.PHP)
        if "nginx" in lower and TechnologyStack.NGINX not in self.technologies:
            self.technologies.append(TechnologyStack.NGINX)
        if "apache" in lower and TechnologyStack.APACHE not in self.technologies:
            self.technologies.append(TechnologyStack.APACHE)

    def classify_target(self) -> None:
        """Auto-detect target type from the target string."""
        t = self.target.lower()
        if t.startswith(("http://", "https://")) or "/" in t:
            if "api" in t or "/v1" in t or "/v2" in t or "/graphql" in t:
                self.target_type = TargetType.API_ENDPOINT
            else:
                self.target_type = TargetType.WEB_APPLICATION
        elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", t):
            self.target_type = TargetType.NETWORK_HOST
        elif "." in t and not t.endswith((".exe", ".bin", ".elf", ".out")):
            # It's a domain
            self.target_type = TargetType.WEB_APPLICATION
        self.confidence_score = 0.7


# ─── Attack Step & Chain ──────────────────────────────────────────────────────

@dataclass
class AttackStep:
    tool: str
    parameters: dict[str, Any]
    expected_outcome: str
    success_probability: float
    execution_time_estimate: int     # seconds
    priority: int = 0
    dependencies: list[str] = field(default_factory=list)


class AttackChain:
    """An ordered multi-tool attack plan for a target."""

    def __init__(self, target_profile: TargetProfile):
        self.target_profile = target_profile
        self.steps: list[AttackStep] = []
        self.success_probability: float = 0.0
        self.estimated_time: int = 0

    def add_step(self, step: AttackStep) -> None:
        self.steps.append(step)
        self.estimated_time += step.execution_time_estimate

    def calculate_success_probability(self) -> None:
        if not self.steps:
            self.success_probability = 0.0
            return
        prob = 1.0
        for s in self.steps:
            prob *= s.success_probability
        self.success_probability = round(prob, 3)

    def to_plan_text(self) -> str:
        lines = [
            f"## AI Attack Plan — {self.target_profile.target}",
            f"**Target type:** {self.target_profile.target_type.value}",
            f"**Estimated duration:** ~{self.estimated_time // 60}m {self.estimated_time % 60}s",
            "",
            "### Planned Steps",
        ]
        for i, s in enumerate(self.steps, 1):
            lines.append(f"{i}. **{s.tool}** — {s.expected_outcome} (ETA {s.execution_time_estimate}s)")
        return "\n".join(lines)

    def next_tool(self, executed: set[str]) -> AttackStep | None:
        """Return the next unexecuted step whose dependencies are satisfied."""
        for step in self.steps:
            if step.tool in executed:
                continue
            if all(dep in executed for dep in step.dependencies):
                return step
        return None


# ─── Intelligent Decision Engine ──────────────────────────────────────────────

class IntelligentDecisionEngine:
    """
    HexStrike-style tool selection and attack chain planning.
    Selects the optimal sequence of tools based on target type and
    what has already been discovered.
    """

    # Tool effectiveness scores by target type
    TOOL_EFFECTIVENESS: dict[str, dict[str, float]] = {
        TargetType.WEB_APPLICATION.value: {
            "nmap":       0.80,
            "whatweb":    0.85,
            "gobuster":   0.90,
            "nuclei":     0.95,
            "nikto":      0.85,
            "sqlmap":     0.90,
            "wpscan":     0.95,  # only if WordPress detected
            "sslyze":     0.80,
            "xssstrike":  0.85,
            "commix":     0.80,
            "dirb":       0.75,
            "curl":       0.70,
        },
        TargetType.NETWORK_HOST.value: {
            "nmap":       0.95,
            "masscan":    0.92,
            "enum4linux": 0.80,
            "smbclient":  0.75,
            "hydra":      0.80,
            "amass":      0.70,
            "dnsrecon":   0.75,
        },
        TargetType.API_ENDPOINT.value: {
            "nuclei":     0.90,
            "curl":       0.90,
            "sqlmap":     0.85,
            "gobuster":   0.85,
            "nikto":      0.80,
        },
        TargetType.DOMAIN.value: {
            "subfinder":  0.90,
            "amass":      0.88,
            "fierce":     0.80,
            "dnsrecon":   0.85,
            "nmap":       0.75,
            "whatweb":    0.80,
            "nuclei":     0.88,
        },
        TargetType.UNKNOWN.value: {
            "nmap":       0.90,
            "whatweb":    0.80,
            "nuclei":     0.85,
        },
    }

    # Attack patterns by scenario — ordered tool chains
    ATTACK_PATTERNS: dict[str, list[dict[str, Any]]] = {
        "web_recon": [
            {"tool": "nmap",     "priority": 1, "time": 60,  "prob": 0.95, "outcome": "Discover open ports & services",        "params": {"flags": "-sV -sC --open -p 80,443,8080,8443,8000,8888"}},
            {"tool": "whatweb",  "priority": 2, "time": 30,  "prob": 0.90, "outcome": "Identify tech stack & CMS",              "params": {}},
            {"tool": "gobuster", "priority": 3, "time": 120, "prob": 0.85, "outcome": "Find hidden directories & files",        "params": {}},
            {"tool": "nuclei",   "priority": 4, "time": 180, "prob": 0.92, "outcome": "Scan for CVEs & known vulnerabilities",  "params": {"templates": "cves"}},
            {"tool": "nikto",    "priority": 5, "time": 120, "prob": 0.85, "outcome": "Web server misconfiguration check",      "params": {}},
        ],
        "network_recon": [
            {"tool": "nmap",       "priority": 1, "time": 90,  "prob": 0.97, "outcome": "Full port scan with service detection", "params": {"flags": "-sV -sC -p-"}},
            {"tool": "masscan",    "priority": 2, "time": 60,  "prob": 0.92, "outcome": "Rapid port discovery",                 "params": {"ports": "1-65535", "rate": "1000"}},
            {"tool": "enum4linux", "priority": 3, "time": 60,  "prob": 0.80, "outcome": "SMB/Windows enumeration",              "params": {}},
        ],
        "domain_recon": [
            {"tool": "subfinder", "priority": 1, "time": 60,  "prob": 0.92, "outcome": "Passive subdomain enumeration",        "params": {}},
            {"tool": "amass",     "priority": 2, "time": 120, "prob": 0.88, "outcome": "Active subdomain + OSINT",             "params": {}},
            {"tool": "dnsrecon",  "priority": 3, "time": 45,  "prob": 0.85, "outcome": "DNS zone transfers & records",         "params": {}},
            {"tool": "fierce",    "priority": 4, "time": 60,  "prob": 0.80, "outcome": "DNS brute force",                     "params": {}},
            {"tool": "nmap",      "priority": 5, "time": 90,  "prob": 0.90, "outcome": "Service scan on discovered hosts",     "params": {"flags": "-sV --open"}},
        ],
        "full_assessment": [
            {"tool": "nmap",     "priority": 1, "time": 90,  "prob": 0.97, "outcome": "Port & service scan",                  "params": {"flags": "-sV -sC --open"}},
            {"tool": "whatweb",  "priority": 2, "time": 30,  "prob": 0.90, "outcome": "Technology fingerprinting",            "params": {}},
            {"tool": "gobuster", "priority": 3, "time": 120, "prob": 0.85, "outcome": "Directory enumeration",                "params": {}},
            {"tool": "nuclei",   "priority": 4, "time": 180, "prob": 0.92, "outcome": "CVE & vulnerability scan",             "params": {"templates": "cves"}},
            {"tool": "nikto",    "priority": 5, "time": 120, "prob": 0.85, "outcome": "Web server audit",                    "params": {}},
            {"tool": "sslyze",   "priority": 6, "time": 45,  "prob": 0.80, "outcome": "SSL/TLS analysis",                    "params": {}},
        ],
        "wordpress": [
            {"tool": "nmap",     "priority": 1, "time": 60,  "prob": 0.95, "outcome": "Port scan",                           "params": {"flags": "-sV --open -p 80,443"}},
            {"tool": "whatweb",  "priority": 2, "time": 30,  "prob": 0.90, "outcome": "Confirm WordPress + plugins",         "params": {}},
            {"tool": "wpscan",   "priority": 3, "time": 120, "prob": 0.95, "outcome": "WordPress vuln & plugin scan",        "params": {}},
            {"tool": "nuclei",   "priority": 4, "time": 180, "prob": 0.90, "outcome": "Template-based CVE scan",             "params": {"templates": "cves"}},
        ],
        "api_testing": [
            {"tool": "nmap",    "priority": 1, "time": 60,  "prob": 0.95, "outcome": "Port scan",                            "params": {"flags": "-sV --open"}},
            {"tool": "curl",    "priority": 2, "time": 10,  "prob": 0.99, "outcome": "HTTP probe & header analysis",         "params": {"flags": "-sIL"}},
            {"tool": "nuclei",  "priority": 3, "time": 180, "prob": 0.90, "outcome": "API vulnerability templates",          "params": {"templates": "cves"}},
            {"tool": "gobuster","priority": 4, "time": 120, "prob": 0.85, "outcome": "API endpoint enumeration",             "params": {}},
            {"tool": "sqlmap",  "priority": 5, "time": 120, "prob": 0.85, "outcome": "SQL injection testing",               "params": {"flags": "--batch --level=2"}},
        ],
        "ssl_check": [
            {"tool": "sslyze",  "priority": 1, "time": 45,  "prob": 0.90, "outcome": "Full SSL/TLS audit",                  "params": {}},
            {"tool": "nmap",    "priority": 2, "time": 60,  "prob": 0.90, "outcome": "SSL-focused nmap scripts",            "params": {"flags": "-sV --script ssl-enum-ciphers,ssl-cert"}},
        ],
    }

    # Fallback tool alternatives (when a tool fails/not installed)
    FALLBACK_TOOLS: dict[str, list[str]] = {
        "gobuster":  ["dirb", "dirsearch", "ffuf"],
        "nuclei":    ["nikto", "whatweb"],
        "whatweb":   ["curl", "nmap"],
        "sslyze":    ["testssl", "nmap"],
        "wpscan":    ["nuclei", "nikto"],
        "subfinder": ["amass", "fierce", "dnsrecon"],
        "amass":     ["subfinder", "fierce"],
        "masscan":   ["nmap"],
        "xssstrike": ["nuclei"],
        "commix":    ["nuclei"],
    }

    def __init__(self):
        pass

    def classify_objective(self, objective: str, target: str) -> str:
        """
        Classify the user's objective into an attack pattern name.
        Returns one of the ATTACK_PATTERNS keys.
        """
        obj = objective.lower()
        tgt = target.lower()

        # Explicit overrides
        if any(kw in obj for kw in ["full", "complete", "comprehensive", "assess", "pentest", "penetration"]):
            return "full_assessment"
        if any(kw in obj for kw in ["wordpress", "wp-admin", "wp-login"]):
            return "wordpress"
        if any(kw in obj for kw in ["ssl", "tls", "certificate", "https check"]):
            return "ssl_check"
        if any(kw in obj for kw in ["api", "graphql", "rest", "endpoint", "swagger"]):
            return "api_testing"
        if any(kw in obj for kw in ["subdomain", "domain", "amass", "subfinder", "dns"]):
            return "domain_recon"
        if any(kw in obj for kw in ["network", "host", "smb", "ssh", "ftp", "ip scan", "cidr"]):
            return "network_recon"

        # Classify from target string
        if tgt.startswith(("http://", "https://")) or "/" in tgt:
            return "web_recon"
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", tgt):
            return "network_recon"
        if "." in tgt and len(tgt.split(".")) >= 2:
            return "web_recon"  # domain → assume web

        return "web_recon"

    def build_attack_chain(
        self,
        profile: TargetProfile,
        objective: str,
        installed_tools: set[str],
    ) -> AttackChain:
        """
        Build an ordered AttackChain for the given target profile and objective.
        Skips tools that are not installed, substituting fallbacks where possible.
        """
        pattern_name = self.classify_objective(objective, profile.target)
        pattern = self.ATTACK_PATTERNS.get(pattern_name, self.ATTACK_PATTERNS["web_recon"])

        # Specialise: if WordPress CMS detected, upgrade to wordpress chain
        if profile.cms_type == "wordpress" and pattern_name not in ("wordpress",):
            pattern = self.ATTACK_PATTERNS["wordpress"]

        chain = AttackChain(profile)

        for step_def in pattern:
            tool = step_def["tool"]

            # Try fallbacks if primary tool not installed
            final_tool = tool
            if installed_tools and tool not in installed_tools:
                for fallback in self.FALLBACK_TOOLS.get(tool, []):
                    if fallback in installed_tools:
                        final_tool = fallback
                        break
                else:
                    # Neither primary nor fallback available — skip step
                    continue

            # Merge base params with any profile-specific overrides
            params = dict(step_def.get("params", {}))
            params["target"] = profile.target

            chain.add_step(AttackStep(
                tool=final_tool,
                parameters=params,
                expected_outcome=step_def["outcome"],
                success_probability=step_def["prob"],
                execution_time_estimate=step_def["time"],
                priority=step_def["priority"],
            ))

        chain.calculate_success_probability()
        return chain

    def get_fallback_tool(self, failed_tool: str, installed_tools: set[str]) -> str | None:
        """Return an alternative tool if the primary one failed."""
        base_name = failed_tool[:-5] if failed_tool.endswith("_scan") else failed_tool
        for fallback in self.FALLBACK_TOOLS.get(base_name, []):
            if not installed_tools or fallback in installed_tools:
                return f"{fallback}_scan" if failed_tool.endswith("_scan") else fallback
        return None

    def score_tools_for_target(
        self, target_type: TargetType, top_n: int = 5
    ) -> list[tuple[str, float]]:
        """Return the top-N tools ranked by effectiveness for a target type."""
        scores = self.TOOL_EFFECTIVENESS.get(target_type.value, {})
        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        return ranked[:top_n]
