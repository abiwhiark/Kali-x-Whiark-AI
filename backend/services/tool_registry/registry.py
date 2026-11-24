"""
Kali AI - Tool Registry
Central registry of all security tools the agent can use.
Each tool has a definition (metadata) and an executor function.
Stage 2: Real subprocess executors for Nmap, WhatWeb, Nuclei with mock fallback.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import shutil
import socket
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

from backend.models.schemas import (
    ToolDefinition, ToolCategory, ToolStatus, RiskLevel,
    ToolCallRequest, ToolCallResult,
)

# Type alias for tool executor functions
ToolExecutor = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


class ToolRegistry:
    """
    Manages the set of tools available to the AI agent.
    Stores definitions (what Gemini sees) and executors (what actually runs).
    """

    def __init__(self) -> None:
        self._definitions: dict[str, ToolDefinition] = {}
        self._executors: dict[str, ToolExecutor] = {}

    def register(self, definition: ToolDefinition, executor: ToolExecutor) -> None:
        """Register a tool with its definition and executor."""
        self._definitions[definition.id] = definition
        self._executors[definition.id] = executor

    def get_definition(self, tool_id: str) -> ToolDefinition | None:
        return self._definitions.get(tool_id)

    def get_all_definitions(self) -> list[ToolDefinition]:
        return list(self._definitions.values())

    def tool_exists(self, tool_id: str) -> bool:
        return tool_id in self._definitions

    async def execute(self, request: ToolCallRequest, timeout: int = 120) -> ToolCallResult:
        """Execute a registered tool with timeout protection."""
        if request.tool_id not in self._executors:
            return ToolCallResult(
                tool_id=request.tool_id,
                success=False,
                error=f"Tool '{request.tool_id}' not found in registry.",
            )

        executor = self._executors[request.tool_id]
        start = time.monotonic()

        try:
            output = await asyncio.wait_for(executor(request.arguments), timeout=timeout)
            elapsed = time.monotonic() - start
            return ToolCallResult(
                tool_id=request.tool_id,
                success=True,
                output=output,
                execution_time=round(elapsed, 2),
            )
        except asyncio.TimeoutError:
            return ToolCallResult(
                tool_id=request.tool_id,
                success=False,
                error=f"Tool execution timed out after {timeout}s.",
                execution_time=float(timeout),
            )
        except Exception as e:
            elapsed = time.monotonic() - start
            return ToolCallResult(
                tool_id=request.tool_id,
                success=False,
                error=str(e),
                execution_time=round(elapsed, 2),
            )


# ──────────────────────────────────────────────
# NETWORK SCANNING HELPERS & FALLBACK ENGINE
# ──────────────────────────────────────────────

def _clean_target_for_network_scan(target: str) -> str:
    """Extract bare hostname or IP from target string, stripping scheme, path, and port."""
    t = (target or "").strip()
    if "://" in t:
        try:
            parsed = urlparse(t)
            t = parsed.hostname or t
        except Exception:
            pass
    # Strip path or trailing slashes
    t = t.split("/")[0]
    # Strip port if present (e.g. localhost:8000 -> localhost)
    if ":" in t and not t.startswith("["):
        parts = t.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            t = parts[0]
    return t or "localhost"


COMMON_PORTS_QUICK: list[tuple[int, str]] = [
    (21, "ftp"), (22, "ssh"), (23, "telnet"), (25, "smtp"), (53, "dns"),
    (80, "http"), (110, "pop3"), (111, "rpcbind"), (135, "msrpc"), (139, "netbios-ssn"),
    (143, "imap"), (443, "https"), (445, "microsoft-ds"), (993, "imaps"), (995, "pop3s"),
    (1433, "ms-sql-s"), (1521, "oracle"), (3000, "http-dev"), (3306, "mysql"),
    (3389, "ms-wbt-server"), (5000, "http-dev"), (5432, "postgresql"), (5900, "vnc"),
    (6379, "redis"), (8000, "http-alt"), (8080, "http-proxy"), (8443, "https-alt"),
    (8888, "http-alt"), (9000, "cslistener"), (27017, "mongodb")
]

COMMON_PORTS_STANDARD: list[tuple[int, str]] = COMMON_PORTS_QUICK + [
    (7, "echo"), (20, "ftp-data"), (69, "tftp"), (79, "finger"), (88, "kerberos"),
    (102, "iso-tsap"), (113, "ident"), (119, "nntp"), (123, "ntp"), (137, "netbios-ns"),
    (138, "netbios-dgm"), (161, "snmp"), (162, "snmptrap"), (179, "bgp"), (389, "ldap"),
    (465, "smtps"), (514, "syslog"), (515, "printer"), (587, "submission"), (636, "ldaps"),
    (873, "rsync"), (990, "ftps"), (1080, "socks"), (1099, "rmiregistry"), (1194, "openvpn"),
    (1723, "pptp"), (1883, "mqtt"), (2049, "nfs"), (2082, "cpanel"), (2083, "cpanel-ssl"),
    (2086, "whm"), (2087, "whm-ssl"), (2181, "zookeeper"), (2375, "docker"), (2376, "docker-ssl"),
    (2379, "etcd"), (3128, "squid"), (3268, "globalcatLDAP"), (4369, "epmd"), (5672, "amqp"),
    (5985, "winrm-http"), (5986, "winrm-https"), (6000, "x11"), (6443, "k8s-api"), (7001, "weblogic"),
    (8008, "http-alt"), (8081, "http-alt"), (8088, "radan-http"), (8444, "https-alt"), (8500, "consul"),
    (9200, "elasticsearch"), (9300, "elasticsearch-cluster"), (9418, "git"), (9999, "abyss"),
    (11211, "memcached"), (15672, "rabbitmq-mgmt"), (28017, "mongodb-web")
]


async def _socket_port_scan(target: str, profile: str = "quick") -> list[dict[str, Any]]:
    """Perform real, non-blocking asynchronous TCP connect port scan on target."""
    host = _clean_target_for_network_scan(target)
    try:
        resolved_ip = socket.gethostbyname(host)
    except Exception:
        resolved_ip = host

    port_list = COMMON_PORTS_STANDARD if profile in ("standard", "service_detection") else COMMON_PORTS_QUICK

    def _sync_probe(port: int, svc: str) -> dict[str, Any] | None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        try:
            res = s.connect_ex((resolved_ip, port))
            if res == 0:
                return {"port": port, "state": "open", "service": svc, "version": ""}
        except Exception:
            pass
        finally:
            s.close()
        return None

    loop = asyncio.get_running_loop()
    tasks = [loop.run_in_executor(None, _sync_probe, p, s) for p, s in port_list]
    try:
        results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=3.0)
        return [r for r in results if r is not None]
    except Exception:
        return []


# ──────────────────────────────────────────────
# MOCK / FALLBACK TOOL EXECUTORS  (Stage 1)
# ──────────────────────────────────────────────

async def _mock_nmap(args: dict[str, Any]) -> dict[str, Any]:
    """
    Nmap port scan fallback engine.
    Used when nmap CLI binary is not installed on the system.
    Returns simulated port discovery results instantly without blocking.
    """
    raw_target = args.get("target", "localhost")
    profile = args.get("profile", "quick")
    target = _clean_target_for_network_scan(raw_target)

    if "testphp.vulnweb.com" in target or "vulnweb" in target:
        ports = [
            {"port": 80, "state": "open", "service": "http", "version": "nginx/1.19.0"},
            {"port": 443, "state": "open", "service": "https", "version": "nginx/1.19.0"},
            {"port": 3306, "state": "open", "service": "mysql", "version": "MySQL 5.7.33"},
        ]
        os_guess = "Linux (Ubuntu/Debian)"
    elif target in ("localhost", "127.0.0.1"):
        ports = [
            {"port": 22, "state": "open", "service": "ssh", "version": "OpenSSH 9.6p1"},
            {"port": 80, "state": "open", "service": "http", "version": "Apache/2.4.58"},
            {"port": 443, "state": "open", "service": "https", "version": "OpenSSL/3.0.13"},
        ]
        os_guess = "Windows" if sys.platform == "win32" else "Linux"
    else:
        ports = [
            {"port": 80, "state": "open", "service": "http", "version": "nginx/1.24.0"},
            {"port": 443, "state": "open", "service": "https", "version": "OpenSSL/3.0.11"},
            {"port": 22, "state": "open", "service": "ssh", "version": "OpenSSH 8.9p1"},
        ]
        os_guess = "Linux"

    return {
        "tool": "nmap",
        "mock": True,
        "engine": "mock_fallback",
        "target": target,
        "profile": profile,
        "ports": ports,
        "os_guess": os_guess,
        "scan_time": "0.15s",
        "note": "Simulated scan results (Nmap CLI binary was not detected on system PATH).",
    }


async def _mock_whatweb(args: dict[str, Any]) -> dict[str, Any]:
    """Mock WhatWeb technology detection."""
    await asyncio.sleep(random.uniform(0.3, 1.0))
    target = args.get("target", "unknown")
    return {
        "tool": "whatweb",
        "mock": True,
        "target": target,
        "technologies": [
            {"name": "nginx", "version": "1.24.0", "category": "Web Server"},
            {"name": "WordPress", "version": "6.4.2", "category": "CMS"},
            {"name": "PHP", "version": "8.2", "category": "Programming Language"},
            {"name": "jQuery", "version": "3.7.1", "category": "JavaScript Library"},
            {"name": "Bootstrap", "version": "5.3", "category": "CSS Framework"},
        ],
        "headers": {
            "Server": "nginx/1.24.0",
            "X-Powered-By": "PHP/8.2",
        },
    }


async def _mock_nuclei(args: dict[str, Any]) -> dict[str, Any]:
    """Mock Nuclei vulnerability scan."""
    await asyncio.sleep(random.uniform(1.0, 2.0))
    target = args.get("target", "unknown")
    templates = args.get("templates", "default")
    return {
        "tool": "nuclei",
        "mock": True,
        "target": target,
        "templates_used": templates,
        "vulnerabilities": [
            {
                "template_id": "wordpress-xmlrpc-login",
                "name": "WordPress XML-RPC Login Detection",
                "severity": "medium",
                "matched_at": f"{target}/xmlrpc.php",
                "description": "XML-RPC interface is accessible and may allow brute-force attacks.",
            },
            {
                "template_id": "missing-csp",
                "name": "Missing Content-Security-Policy Header",
                "severity": "informational",
                "matched_at": target,
                "description": "Content-Security-Policy header is not set.",
            },
            {
                "template_id": "x-frame-options-missing",
                "name": "Missing X-Frame-Options Header",
                "severity": "low",
                "matched_at": target,
                "description": "X-Frame-Options header is missing, potential clickjacking risk.",
            },
        ],
        "total_requests": 1247,
        "scan_time": "15.2s",
    }


async def _mock_nikto(args: dict[str, Any]) -> dict[str, Any]:
    """Mock Nikto web server analysis."""
    await asyncio.sleep(random.uniform(0.8, 1.5))
    target = args.get("target", "unknown")
    return {
        "tool": "nikto",
        "mock": True,
        "target": target,
        "findings": [
            {
                "id": "000726",
                "description": "Server may allow directory listing",
                "uri": "/icons/",
                "method": "GET",
            },
            {
                "id": "003587",
                "description": "PHP version may be outdated",
                "uri": "/",
                "method": "GET",
            },
        ],
        "server": "nginx/1.24.0",
        "scan_time": "32.1s",
    }


async def _mock_sslyze(args: dict[str, Any]) -> dict[str, Any]:
    """Mock SSLyze TLS analysis."""
    await asyncio.sleep(random.uniform(0.5, 1.2))
    target = args.get("target", "unknown")
    return {
        "tool": "sslyze",
        "mock": True,
        "target": target,
        "certificate": {
            "subject": f"CN={target}",
            "issuer": "Let's Encrypt Authority X3",
            "valid_from": "2024-01-15",
            "valid_until": "2025-04-15",
            "is_valid": True,
        },
        "protocols": {
            "TLS 1.3": "enabled",
            "TLS 1.2": "enabled",
            "TLS 1.1": "disabled",
            "TLS 1.0": "disabled",
            "SSL 3.0": "disabled",
        },
        "vulnerabilities": {
            "heartbleed": False,
            "robot": False,
            "crime": False,
        },
        "cipher_suites": {
            "strong": ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
            "weak": [],
        },
    }


async def _mock_zap(args: dict[str, Any]) -> dict[str, Any]:
    """Mock OWASP ZAP passive scan."""
    await asyncio.sleep(random.uniform(1.0, 2.0))
    target = args.get("target", "unknown")
    scan_type = args.get("scan_type", "passive")
    return {
        "tool": "owasp_zap",
        "mock": True,
        "target": target,
        "scan_type": scan_type,
        "alerts": [
            {
                "name": "Cookie Without Secure Flag",
                "risk": "low",
                "confidence": "medium",
                "url": target,
                "description": "A cookie has been set without the secure flag.",
            },
            {
                "name": "Missing Anti-clickjacking Header",
                "risk": "medium",
                "confidence": "medium",
                "url": target,
                "description": "The response does not include anti-clickjacking headers.",
            },
        ],
        "urls_crawled": 23,
        "scan_time": "45.7s",
    }


async def _mock_gobuster(args: dict[str, Any]) -> dict[str, Any]:
    """Mock Gobuster directory discovery."""
    await asyncio.sleep(random.uniform(0.8, 1.5))
    target = args.get("target", "unknown")
    return {
        "tool": "gobuster",
        "mock": True,
        "target": target,
        "discovered_paths": [
            {"path": "/admin", "status": 302, "size": 0},
            {"path": "/login", "status": 200, "size": 4523},
            {"path": "/wp-admin", "status": 302, "size": 0},
            {"path": "/robots.txt", "status": 200, "size": 128},
            {"path": "/sitemap.xml", "status": 200, "size": 2048},
        ],
        "wordlist": "common.txt",
        "scan_time": "28.3s",
    }


# ──────────────────────────────────────────────
# REAL TOOL EXECUTORS  (Stage 2)
# These run actual binaries via subprocess.
# Used only when the binary is detected on PATH.
# ──────────────────────────────────────────────

async def _real_nmap(args: dict[str, Any]) -> dict[str, Any]:
    """Real Nmap scan via subprocess with auto-detected binary, -Pn flag, and unprivileged safety."""
    raw_target = args.get("target", "localhost")
    profile = args.get("profile", "quick")
    target = _clean_target_for_network_scan(raw_target)

    nmap_bin = _find_binary("nmap") or "nmap"

    # Always include -Pn so firewalled ICMP ping probes don't cause false negatives
    # On Windows without raw socket driver, -sT avoids Npcap privilege errors
    unprivileged_flags = ["-sT"] if sys.platform == "win32" else []

    profiles = {
        "quick": ["-Pn", "-F", "--open"],                              # top 100 ports
        "standard": ["-Pn", "--top-ports", "1000", "--open"] + unprivileged_flags,
        "service_detection": ["-Pn", "-sV", "--top-ports", "1000", "--open"] + unprivileged_flags,
    }
    nmap_flags = profiles.get(profile, profiles["quick"])

    cmd = [nmap_bin, "-oX", "-"] + nmap_flags + [target]
    start_time = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=115)
        xml_output = stdout.decode(errors="replace")
        stderr_output = stderr.decode(errors="replace")
    except Exception as e:
        logger.warning("Failed executing nmap binary '%s': %s. Falling back to socket engine.", nmap_bin, e)
        return await _mock_nmap(args)

    elapsed = round(time.monotonic() - start_time, 2)
    ports = []
    os_guess = "Unknown"
    try:
        root = ET.fromstring(xml_output)
        for host in root.findall("host"):
            for port_el in host.findall(".//port"):
                state_el = port_el.find("state")
                svc_el = port_el.find("service")
                if state_el is not None and state_el.get("state") in ("open", "filtered"):
                    ports.append({
                        "port": int(port_el.get("portid", 0)),
                        "state": state_el.get("state", ""),
                        "service": svc_el.get("name", "") if svc_el is not None else "",
                        "version": f"{svc_el.get('product', '')} {svc_el.get('version', '')}".strip() if svc_el is not None else "",
                    })
            os_el = host.find(".//osmatch")
            if os_el is not None:
                os_guess = os_el.get("name", "Unknown")
    except ET.ParseError:
        pass

    # If Nmap didn't find ports or had parsing issues on local host, cross-verify with socket engine
    if not ports and target in ("localhost", "127.0.0.1"):
        logger.info("Nmap returned no ports on localhost; cross-verifying with socket engine.")
        socket_ports = await _socket_port_scan(target, profile)
        if socket_ports:
            ports = socket_ports

    return {
        "tool": "nmap",
        "mock": False,
        "target": target,
        "profile": profile,
        "ports": ports,
        "os_guess": os_guess,
        "scan_time": f"{elapsed}s",
        "raw_xml": xml_output[:4000],
        "stderr": stderr_output[:500],
    }


async def _real_whatweb(args: dict[str, Any]) -> dict[str, Any]:
    """Real WhatWeb scan via subprocess."""
    target = args.get("target", "localhost")
    url = target if target.startswith("http") else f"http://{target}"

    cmd = ["whatweb", "--log-json=-", "--quiet", url]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=55)
    raw = stdout.decode(errors="replace").strip()

    technologies = []
    headers = {}
    try:
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            entries = json.loads(line)
            if isinstance(entries, list):
                for entry in entries:
                    for plugin_name, plugin_data in entry.get("plugins", {}).items():
                        version = ""
                        if isinstance(plugin_data, dict):
                            versions = plugin_data.get("version", [])
                            version = versions[0] if versions else ""
                        technologies.append({
                            "name": plugin_name,
                            "version": version,
                            "category": "Detected",
                        })
                    for hdr_entry in entry.get("plugins", {}).get("HTTPServer", {}).get("string", []):
                        headers["Server"] = hdr_entry
    except (json.JSONDecodeError, KeyError):
        pass

    return {
        "tool": "whatweb",
        "mock": False,
        "target": target,
        "technologies": technologies,
        "headers": headers,
        "raw": raw[:2000],
    }


async def _real_nuclei(args: dict[str, Any]) -> dict[str, Any]:
    """Real Nuclei vulnerability scan via subprocess."""
    target = args.get("target", "localhost")
    templates = args.get("templates", "default")
    url = target if target.startswith("http") else f"http://{target}"

    template_map = {
        "default": [],
        "cves": ["-t", "cves/"],
        "misconfigurations": ["-t", "misconfigurations/"],
        "exposures": ["-t", "exposures/"],
    }
    t_flags = template_map.get(templates, [])

    cmd = ["nuclei", "-u", url, "-json-export", "-", "-silent", "-nc"] + t_flags
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=175)
    raw = stdout.decode(errors="replace")

    vulnerabilities = []
    total_requests = 0
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            finding = json.loads(line)
            vulnerabilities.append({
                "template_id": finding.get("template-id", ""),
                "name": finding.get("info", {}).get("name", ""),
                "severity": finding.get("info", {}).get("severity", "informational"),
                "matched_at": finding.get("matched-at", url),
                "description": finding.get("info", {}).get("description", ""),
            })
            total_requests += 1
        except json.JSONDecodeError:
            pass

    return {
        "tool": "nuclei",
        "mock": False,
        "target": target,
        "templates_used": templates,
        "vulnerabilities": vulnerabilities,
        "total_requests": total_requests,
        "raw": raw[:3000],
    }


# ──────────────────────────────────────────────
# AUTO-DETECTION HELPER
# ──────────────────────────────────────────────

def _find_binary(binary_name: str) -> str | None:
    """Find binary on PATH or standard OS installation locations."""
    bin_path = shutil.which(binary_name)
    if bin_path:
        return bin_path

    if sys.platform == "win32":
        win_locations: dict[str, list[str]] = {
            "nmap": [
                r"C:\Program Files\Nmap\nmap.exe",
                r"C:\Program Files (x86)\Nmap\nmap.exe",
                r"C:\Nmap\nmap.exe",
                os.path.expandvars(r"%LOCALAPPDATA%\Programs\Nmap\nmap.exe"),
            ],
            "whatweb": [
                r"C:\Tools\whatweb\whatweb",
                os.path.expandvars(r"%LOCALAPPDATA%\Programs\whatweb\whatweb"),
            ],
            "nuclei": [
                r"C:\Tools\nuclei.exe",
                os.path.expandvars(r"%USERPROFILE%\go\bin\nuclei.exe"),
            ],
        }
        for candidate in win_locations.get(binary_name, []):
            if os.path.exists(candidate):
                return candidate
    return None


def _pick_executor(
    real_fn: ToolExecutor,
    mock_fn: ToolExecutor,
    binary_name: str,
) -> tuple[ToolExecutor, ToolStatus]:
    """Return (executor, status) — real if binary found on PATH or standard paths, mock otherwise."""
    if _find_binary(binary_name):
        return real_fn, ToolStatus.AVAILABLE
    return mock_fn, ToolStatus.MOCK


# ──────────────────────────────────────────────
# REGISTRY FACTORY
# ──────────────────────────────────────────────

def create_registry() -> ToolRegistry:
    """
    Create a ToolRegistry pre-loaded with all 7 security tools.
    Nmap, WhatWeb, and Nuclei auto-detect their real binary and fall back
    to mock executors when not installed. Nikto, SSLyze, ZAP, and Gobuster
    remain mock-only for now.
    """
    registry = ToolRegistry()

    # 1 — Nmap
    nmap_executor, nmap_status = _pick_executor(_real_nmap, _mock_nmap, "nmap")
    registry.register(
        ToolDefinition(
            id="nmap_scan",
            name="Nmap Port Scanner",
            description="Discovers open ports, running services, and OS fingerprinting on a target host. Use restricted scan profiles only.",
            category=ToolCategory.RECONNAISSANCE,
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP or hostname to scan."},
                    "profile": {
                        "type": "string",
                        "enum": ["quick", "standard", "service_detection"],
                        "description": "Scan profile: quick (top 100 ports), standard (top 1000), service_detection (version detection).",
                    },
                },
                "required": ["target"],
            },
            status=nmap_status,
            risk_level=RiskLevel.MEDIUM,
            timeout=120,
        ),
        nmap_executor,
    )

    # 2 — WhatWeb
    whatweb_executor, whatweb_status = _pick_executor(_real_whatweb, _mock_whatweb, "whatweb")
    registry.register(
        ToolDefinition(
            id="whatweb_scan",
            name="WhatWeb Technology Identifier",
            description="Identifies web technologies, CMS, frameworks, web servers, and JavaScript libraries used by a target website.",
            category=ToolCategory.WEB_ANALYSIS,
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL to analyze."},
                },
                "required": ["target"],
            },
            status=whatweb_status,
            risk_level=RiskLevel.LOW,
            timeout=60,
        ),
        whatweb_executor,
    )

    # 3 — Nuclei
    nuclei_executor, nuclei_status = _pick_executor(_real_nuclei, _mock_nuclei, "nuclei")
    registry.register(
        ToolDefinition(
            id="nuclei_scan",
            name="Nuclei Vulnerability Scanner",
            description="Scans for known vulnerabilities, misconfigurations, and exposures using template-based detection.",
            category=ToolCategory.VULNERABILITY_SCAN,
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL or host to scan."},
                    "templates": {
                        "type": "string",
                        "enum": ["default", "cves", "misconfigurations", "exposures"],
                        "description": "Template category to use.",
                    },
                },
                "required": ["target"],
            },
            status=nuclei_status,
            risk_level=RiskLevel.MEDIUM,
            timeout=180,
        ),
        nuclei_executor,
    )

    # 4 — Nikto (mock only)
    registry.register(
        ToolDefinition(
            id="nikto_scan",
            name="Nikto Web Server Scanner",
            description="Performs comprehensive tests against web servers for dangerous files, outdated software, and configuration issues.",
            category=ToolCategory.WEB_ANALYSIS,
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL or host to scan."},
                },
                "required": ["target"],
            },
            status=ToolStatus.MOCK,
            risk_level=RiskLevel.MEDIUM,
            timeout=180,
        ),
        _mock_nikto,
    )

    # 5 — SSLyze (mock only)
    registry.register(
        ToolDefinition(
            id="sslyze_scan",
            name="SSLyze TLS/SSL Analyzer",
            description="Analyzes TLS/SSL configuration including certificate validity, protocol versions, cipher suites, and known vulnerabilities.",
            category=ToolCategory.SSL_TLS,
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target hostname to analyze TLS/SSL configuration."},
                },
                "required": ["target"],
            },
            status=ToolStatus.MOCK,
            risk_level=RiskLevel.LOW,
            timeout=90,
        ),
        _mock_sslyze,
    )

    # 6 — OWASP ZAP (mock only)
    registry.register(
        ToolDefinition(
            id="zap_scan",
            name="OWASP ZAP Scanner",
            description="Performs passive or active web application security analysis including security headers, cookies, and common vulnerabilities.",
            category=ToolCategory.WEB_ANALYSIS,
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL to scan."},
                    "scan_type": {
                        "type": "string",
                        "enum": ["passive", "active"],
                        "description": "Scan type. Active scanning requires explicit authorization.",
                    },
                },
                "required": ["target"],
            },
            status=ToolStatus.MOCK,
            risk_level=RiskLevel.HIGH,
            timeout=300,
            permission_requirements=["explicit_authorization_for_active"],
        ),
        _mock_zap,
    )

    # 7 — Gobuster (mock only)
    registry.register(
        ToolDefinition(
            id="gobuster_scan",
            name="Gobuster Directory Scanner",
            description="Discovers hidden directories and files on a web server using wordlist-based brute-force.",
            category=ToolCategory.DISCOVERY,
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL to scan."},
                    "wordlist": {
                        "type": "string",
                        "enum": ["common", "small", "medium"],
                        "description": "Wordlist size to use.",
                    },
                },
                "required": ["target"],
            },
            status=ToolStatus.MOCK,
            risk_level=RiskLevel.MEDIUM,
            timeout=180,
        ),
        _mock_gobuster,
    )

    return registry


# Backward-compatible alias
def create_default_registry() -> ToolRegistry:
    """Alias for create_registry() — kept for backward compatibility."""
    return create_registry()
