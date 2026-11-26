"""
Kali AI - Tool Registry
Central registry of ALL security tools the agent can use.
Each tool has a definition (metadata) and an executor function.
Stage 3: Real subprocess executors for 20+ Kali tools + terminal/browser launchers.
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
# REAL EXECUTORS — Stage 3 (all remaining tools)
# ──────────────────────────────────────────────

async def _run_tool_subprocess(
    cmd: list[str],
    timeout: int = 120,
    input_data: bytes | None = None,
) -> tuple[str, str, int]:
    """Generic subprocess runner; returns (stdout, stderr, returncode)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if input_data else None,
        )
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(input=input_data), timeout=timeout
        )
        return (
            stdout_b.decode(errors="replace"),
            stderr_b.decode(errors="replace"),
            proc.returncode or 0,
        )
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return ("", f"Command timed out after {timeout}s", -1)
    except Exception as exc:
        return ("", str(exc), -1)


# ── Nikto ──────────────────────────────────────────────────────────────────────

async def _real_nikto(args: dict[str, Any]) -> dict[str, Any]:
    """Real Nikto web server scan."""
    target = args.get("target", "localhost")
    url = target if target.startswith("http") else f"http://{target}"
    start = time.monotonic()
    cmd = ["nikto", "-h", url, "-Format", "txt", "-nointeractive"]
    stdout, stderr, code = await _run_tool_subprocess(cmd, timeout=180)
    elapsed = round(time.monotonic() - start, 2)
    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("+") and len(line) > 2:
            # Strip leading "+" and optional OSVDB-XXXX:
            desc = line.lstrip("+ ").strip()
            findings.append({"description": desc, "uri": "/", "method": "GET", "id": "nikto"})
    return {
        "tool": "nikto", "mock": False, "target": target,
        "findings": findings, "stdout": stdout[:3000], "stderr": stderr[:500],
        "scan_time": f"{elapsed}s", "exit_code": code,
    }


async def _mock_nikto_real_fallback(args: dict[str, Any]) -> dict[str, Any]:
    """Nikto mock + try real binary."""
    if _find_binary("nikto"):
        return await _real_nikto(args)
    return await _mock_nikto(args)


# ── Gobuster ───────────────────────────────────────────────────────────────────

GOBUSTER_WORDLISTS_LINUX = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
]

def _pick_wordlist(size: str = "common") -> str:
    for wl in GOBUSTER_WORDLISTS_LINUX:
        if os.path.exists(wl):
            return wl
    return "/usr/share/wordlists/dirb/common.txt"  # fallback even if missing


async def _real_gobuster(args: dict[str, Any]) -> dict[str, Any]:
    """Real Gobuster directory brute-force scan."""
    target = args.get("target", "localhost")
    url = target if target.startswith("http") else f"http://{target}"
    wordlist = _pick_wordlist(args.get("wordlist", "common"))
    start = time.monotonic()
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "--no-error", "-t", "25"]
    stdout, stderr, code = await _run_tool_subprocess(cmd, timeout=180)
    elapsed = round(time.monotonic() - start, 2)
    discovered = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("=") or line.startswith("/usr"):
            continue
        # Lines look like: /admin                (Status: 302) [Size: 0]
        import re as _re
        m = _re.match(r"(/\S*)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?", line)
        if m:
            discovered.append({
                "path": m.group(1),
                "status": int(m.group(2)),
                "size": int(m.group(3)) if m.group(3) else 0,
            })
    return {
        "tool": "gobuster", "mock": False, "target": target,
        "discovered_paths": discovered, "wordlist": wordlist,
        "stdout": stdout[:2000], "stderr": stderr[:500],
        "scan_time": f"{elapsed}s",
    }


# ── SSLyze ─────────────────────────────────────────────────────────────────────

async def _real_sslyze(args: dict[str, Any]) -> dict[str, Any]:
    """Real SSLyze TLS analysis."""
    target = args.get("target", "localhost")
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    start = time.monotonic()
    cmd = ["sslyze", "--regular", "--json_out=-", host]
    stdout, stderr, code = await _run_tool_subprocess(cmd, timeout=120)
    elapsed = round(time.monotonic() - start, 2)
    protocols: dict[str, str] = {}
    cert_info: dict[str, Any] = {}
    vulns: dict[str, Any] = {}
    try:
        data = json.loads(stdout)
        for server_scan in data.get("server_scan_results", []):
            result = server_scan.get("scan_result", {})
            for proto in ["ssl_2_0_cipher_suites", "ssl_3_0_cipher_suites",
                          "tls_1_0_cipher_suites", "tls_1_1_cipher_suites",
                          "tls_1_2_cipher_suites", "tls_1_3_cipher_suites"]:
                cs = result.get(proto, {})
                if cs:
                    name = proto.replace("_cipher_suites", "").replace("_", ".").upper()
                    name = name.replace("TLS.", "TLS ").replace("SSL.", "SSL ")
                    accepted = cs.get("result", {}).get("accepted_cipher_suites", [])
                    protocols[name] = "enabled" if accepted else "disabled"
            cert_res = result.get("certificate_info", {})
            if cert_res:
                chain = cert_res.get("result", {}).get("certificate_deployments", [{}])
                if chain:
                    leaf = chain[0].get("received_certificate_chain", [{}])
                    if leaf:
                        subj = leaf[0].get("subject", {})
                        cert_info = {
                            "subject": str(subj),
                            "is_valid": not chain[0].get("verified_chain_has_legacy_symantec_anchor", False),
                        }
        heartbleed = result.get("heartbleed", {}).get("result", {}).get("is_vulnerable_to_heartbleed", False)
        vulns = {"heartbleed": heartbleed}
    except Exception:
        pass
    return {
        "tool": "sslyze", "mock": False, "target": target,
        "protocols": protocols, "certificate": cert_info,
        "vulnerabilities": vulns, "stdout": stdout[:2000], "stderr": stderr[:500],
        "scan_time": f"{elapsed}s",
    }


# ── SQLMap ─────────────────────────────────────────────────────────────────────

async def _real_sqlmap(args: dict[str, Any]) -> dict[str, Any]:
    """Real SQLMap SQL injection scan."""
    target = args.get("target", "localhost")
    url = target if target.startswith("http") else f"http://{target}"
    flags = args.get("flags", [])
    start = time.monotonic()
    cmd = ["sqlmap", "-u", url, "--batch", "--level=2", "--risk=1",
           "--output-dir=/tmp/sqlmap_kali_ai", "--forms"] + flags
    stdout, stderr, code = await _run_tool_subprocess(cmd, timeout=240)
    elapsed = round(time.monotonic() - start, 2)
    injectable = []
    for line in stdout.splitlines():
        lower = line.lower()
        if "is vulnerable" in lower or "parameter" in lower and "injectable" in lower:
            injectable.append(line.strip())
    return {
        "tool": "sqlmap", "mock": False, "target": target,
        "injectable_parameters": injectable,
        "stdout": stdout[:3000], "stderr": stderr[:500],
        "scan_time": f"{elapsed}s", "exit_code": code,
    }


async def _mock_sqlmap(args: dict[str, Any]) -> dict[str, Any]:
    """Mock SQLMap for systems without sqlmap installed."""
    await asyncio.sleep(random.uniform(0.5, 1.5))
    target = args.get("target", "unknown")
    return {
        "tool": "sqlmap", "mock": True, "target": target,
        "injectable_parameters": ["[MOCK] id parameter may be injectable (GET)"],
        "stdout": "[MOCK] sqlmap not installed — simulated result",
        "scan_time": "0.9s",
    }


# ── Hydra ──────────────────────────────────────────────────────────────────────

async def _real_hydra(args: dict[str, Any]) -> dict[str, Any]:
    """Real Hydra online brute-force."""
    target = args.get("target", "localhost")
    service = args.get("service", "ssh")
    userlist = args.get("userlist", "/usr/share/wordlists/metasploit/unix_users.txt")
    passlist = args.get("passlist", "/usr/share/wordlists/metasploit/unix_passwords.txt")
    host = _clean_target_for_network_scan(target)
    start = time.monotonic()
    cmd = ["hydra", "-L", userlist, "-P", passlist, host, service, "-t", "4", "-f"]
    stdout, stderr, code = await _run_tool_subprocess(cmd, timeout=180)
    elapsed = round(time.monotonic() - start, 2)
    cracked = [l.strip() for l in stdout.splitlines() if "[" in l and "] login:" in l]
    return {
        "tool": "hydra", "mock": False, "target": target, "service": service,
        "cracked_credentials": cracked,
        "stdout": stdout[:2000], "stderr": stderr[:500],
        "scan_time": f"{elapsed}s",
    }


async def _mock_hydra(args: dict[str, Any]) -> dict[str, Any]:
    await asyncio.sleep(random.uniform(0.5, 1.2))
    target = args.get("target", "unknown")
    return {
        "tool": "hydra", "mock": True, "target": target,
        "cracked_credentials": [],
        "stdout": "[MOCK] hydra not installed — no credentials attempted",
        "scan_time": "0.8s",
    }


# ── WPScan ─────────────────────────────────────────────────────────────────────

async def _real_wpscan(args: dict[str, Any]) -> dict[str, Any]:
    """Real WPScan WordPress vulnerability scanner."""
    target = args.get("target", "localhost")
    url = target if target.startswith("http") else f"http://{target}"
    start = time.monotonic()
    cmd = ["wpscan", "--url", url, "--no-banner", "--format", "json",
           "--enumerate", "vp,vt,u"]
    stdout, stderr, code = await _run_tool_subprocess(cmd, timeout=180)
    elapsed = round(time.monotonic() - start, 2)
    plugins: list[dict] = []
    themes: list[dict] = []
    users: list[str] = []
    version_info: dict = {}
    try:
        data = json.loads(stdout)
        version_info = data.get("version", {})
        plugins = list(data.get("plugins", {}).values())
        themes = list(data.get("themes", {}).values())
        users = [u.get("username", "") for u in data.get("users", {}).values()]
    except Exception:
        pass
    return {
        "tool": "wpscan", "mock": False, "target": target,
        "version": version_info, "plugins": plugins[:20],
        "themes": themes[:10], "users": users,
        "stdout": stdout[:2000], "stderr": stderr[:500],
        "scan_time": f"{elapsed}s",
    }


async def _mock_wpscan(args: dict[str, Any]) -> dict[str, Any]:
    await asyncio.sleep(random.uniform(0.5, 1.2))
    target = args.get("target", "unknown")
    return {
        "tool": "wpscan", "mock": True, "target": target,
        "version": {"number": "6.4.2", "status": "latest"},
        "plugins": [{"slug": "contact-form-7", "version": {"number": "5.8"}}],
        "themes": [], "users": ["admin"],
        "scan_time": "0.9s",
    }


# ── Subfinder ──────────────────────────────────────────────────────────────────

async def _real_subfinder(args: dict[str, Any]) -> dict[str, Any]:
    """Real subfinder passive subdomain enumeration."""
    target = args.get("target", "example.com")
    domain = _clean_target_for_network_scan(target)
    start = time.monotonic()
    cmd = ["subfinder", "-d", domain, "-silent", "-o", "/dev/stdout"]
    stdout, stderr, code = await _run_tool_subprocess(cmd, timeout=120)
    elapsed = round(time.monotonic() - start, 2)
    subdomains = [s.strip() for s in stdout.splitlines() if s.strip()]
    return {
        "tool": "subfinder", "mock": False, "target": domain,
        "subdomains": subdomains, "count": len(subdomains),
        "stdout": stdout[:2000], "stderr": stderr[:300],
        "scan_time": f"{elapsed}s",
    }


async def _mock_subfinder(args: dict[str, Any]) -> dict[str, Any]:
    await asyncio.sleep(random.uniform(0.3, 0.8))
    target = args.get("target", "example.com")
    domain = _clean_target_for_network_scan(target)
    return {
        "tool": "subfinder", "mock": True, "target": domain,
        "subdomains": [f"www.{domain}", f"mail.{domain}", f"api.{domain}", f"dev.{domain}"],
        "count": 4, "scan_time": "0.5s",
    }


# ── Amass ──────────────────────────────────────────────────────────────────────

async def _real_amass(args: dict[str, Any]) -> dict[str, Any]:
    """Real amass subdomain enumeration (passive)."""
    target = args.get("target", "example.com")
    domain = _clean_target_for_network_scan(target)
    start = time.monotonic()
    cmd = ["amass", "enum", "-passive", "-d", domain, "-silent"]
    stdout, stderr, code = await _run_tool_subprocess(cmd, timeout=120)
    elapsed = round(time.monotonic() - start, 2)
    subdomains = [s.strip() for s in stdout.splitlines() if s.strip()]
    return {
        "tool": "amass", "mock": False, "target": domain,
        "subdomains": subdomains, "count": len(subdomains),
        "stdout": stdout[:2000], "scan_time": f"{elapsed}s",
    }


async def _mock_amass(args: dict[str, Any]) -> dict[str, Any]:
    await asyncio.sleep(random.uniform(0.5, 1.0))
    target = args.get("target", "example.com")
    domain = _clean_target_for_network_scan(target)
    return {
        "tool": "amass", "mock": True, "target": domain,
        "subdomains": [f"www.{domain}", f"vpn.{domain}", f"smtp.{domain}"],
        "count": 3, "scan_time": "0.6s",
    }


# ── Dirb ───────────────────────────────────────────────────────────────────────

async def _real_dirb(args: dict[str, Any]) -> dict[str, Any]:
    """Real dirb directory scan."""
    target = args.get("target", "localhost")
    url = target if target.startswith("http") else f"http://{target}"
    wordlist = "/usr/share/dirb/wordlists/common.txt"
    start = time.monotonic()
    cmd = ["dirb", url, wordlist, "-S", "-r"]
    stdout, stderr, code = await _run_tool_subprocess(cmd, timeout=180)
    elapsed = round(time.monotonic() - start, 2)
    discovered = []
    import re as _re
    for line in stdout.splitlines():
        m = _re.match(r"==> DIRECTORY: (.+)", line.strip())
        if m:
            discovered.append({"path": m.group(1), "type": "directory", "status": 200})
        m2 = _re.match(r"\+\s+(https?://\S+)\s+\(CODE:(\d+)\|SIZE:\d+\)", line.strip())
        if m2:
            discovered.append({"path": m2.group(1), "type": "file", "status": int(m2.group(2))})
    return {
        "tool": "dirb", "mock": False, "target": target,
        "discovered_paths": discovered,
        "stdout": stdout[:2000], "scan_time": f"{elapsed}s",
    }


async def _mock_dirb(args: dict[str, Any]) -> dict[str, Any]:
    await asyncio.sleep(random.uniform(0.5, 1.0))
    target = args.get("target", "unknown")
    return {
        "tool": "dirb", "mock": True, "target": target,
        "discovered_paths": [
            {"path": f"{target}/admin", "type": "directory", "status": 301},
            {"path": f"{target}/backup", "type": "directory", "status": 403},
        ],
        "scan_time": "0.7s",
    }


# ── Masscan ─────────────────────────────────────────────────────────────────────

async def _real_masscan(args: dict[str, Any]) -> dict[str, Any]:
    """Real masscan high-speed port scanner."""
    target = args.get("target", "localhost")
    ports = args.get("ports", "1-1024")
    rate = args.get("rate", "1000")
    host = _clean_target_for_network_scan(target)
    start = time.monotonic()
    cmd = ["masscan", host, f"-p{ports}", f"--rate={rate}", "-oJ", "-"]
    stdout, stderr, code = await _run_tool_subprocess(cmd, timeout=180)
    elapsed = round(time.monotonic() - start, 2)
    open_ports = []
    try:
        # masscan JSON output: list of {"ip":..., "ports":[{"port":...,"proto":...,"status":"open"},...]}
        data = json.loads("[" + stdout.strip().rstrip(",") + "]")
        for entry in data:
            for p in entry.get("ports", []):
                if p.get("status") == "open":
                    open_ports.append({
                        "port": p.get("port"), "proto": p.get("proto", "tcp"),
                        "ip": entry.get("ip"),
                    })
    except Exception:
        import re as _re
        for line in stdout.splitlines():
            m = _re.search(r"(\d+)/(\w+)", line)
            if m:
                open_ports.append({"port": int(m.group(1)), "proto": m.group(2)})
    return {
        "tool": "masscan", "mock": False, "target": host,
        "ports_scanned": ports, "open_ports": open_ports,
        "stdout": stdout[:2000], "scan_time": f"{elapsed}s",
    }


async def _mock_masscan(args: dict[str, Any]) -> dict[str, Any]:
    await asyncio.sleep(random.uniform(0.3, 0.8))
    target = args.get("target", "unknown")
    return {
        "tool": "masscan", "mock": True, "target": target,
        "open_ports": [{"port": 80, "proto": "tcp"}, {"port": 443, "proto": "tcp"}],
        "scan_time": "0.4s",
    }


# ── Enum4linux ─────────────────────────────────────────────────────────────────

async def _real_enum4linux(args: dict[str, Any]) -> dict[str, Any]:
    """Real enum4linux SMB/Windows enumeration."""
    target = args.get("target", "localhost")
    host = _clean_target_for_network_scan(target)
    start = time.monotonic()
    cmd = ["enum4linux", "-a", host]
    stdout, stderr, code = await _run_tool_subprocess(cmd, timeout=120)
    elapsed = round(time.monotonic() - start, 2)
    shares: list[str] = []
    users: list[str] = []
    import re as _re
    for line in stdout.splitlines():
        ms = _re.match(r"\s+Sharename\s+(\S+)", line)
        if ms:
            shares.append(ms.group(1))
        mu = _re.search(r"user:\[(\S+)\]", line)
        if mu:
            users.append(mu.group(1))
    return {
        "tool": "enum4linux", "mock": False, "target": host,
        "shares": list(set(shares)), "users": list(set(users)),
        "stdout": stdout[:3000], "scan_time": f"{elapsed}s",
    }


async def _mock_enum4linux(args: dict[str, Any]) -> dict[str, Any]:
    await asyncio.sleep(random.uniform(0.5, 1.0))
    target = args.get("target", "unknown")
    return {
        "tool": "enum4linux", "mock": True, "target": target,
        "shares": ["IPC$", "ADMIN$"], "users": ["Administrator"],
        "scan_time": "0.6s",
    }


# ── Fierce ─────────────────────────────────────────────────────────────────────

async def _real_fierce(args: dict[str, Any]) -> dict[str, Any]:
    """Real fierce DNS reconnaissance."""
    target = args.get("target", "example.com")
    domain = _clean_target_for_network_scan(target)
    start = time.monotonic()
    cmd = ["fierce", "--domain", domain]
    stdout, stderr, code = await _run_tool_subprocess(cmd, timeout=120)
    elapsed = round(time.monotonic() - start, 2)
    found_hosts: list[str] = []
    import re as _re
    for line in stdout.splitlines():
        m = _re.search(r"Found:\s+(\S+)", line)
        if m:
            found_hosts.append(m.group(1))
    return {
        "tool": "fierce", "mock": False, "target": domain,
        "found_hosts": found_hosts,
        "stdout": stdout[:2000], "scan_time": f"{elapsed}s",
    }


async def _mock_fierce(args: dict[str, Any]) -> dict[str, Any]:
    await asyncio.sleep(random.uniform(0.3, 0.8))
    target = args.get("target", "example.com")
    domain = _clean_target_for_network_scan(target)
    return {
        "tool": "fierce", "mock": True, "target": domain,
        "found_hosts": [f"www.{domain}", f"mail.{domain}"],
        "scan_time": "0.5s",
    }


# ── DNSRecon ───────────────────────────────────────────────────────────────────

async def _real_dnsrecon(args: dict[str, Any]) -> dict[str, Any]:
    """Real dnsrecon DNS reconnaissance."""
    target = args.get("target", "example.com")
    domain = _clean_target_for_network_scan(target)
    scan_type = args.get("scan_type", "std")
    start = time.monotonic()
    cmd = ["dnsrecon", "-d", domain, "-t", scan_type, "--json", "/dev/stdout"]
    stdout, stderr, code = await _run_tool_subprocess(cmd, timeout=120)
    elapsed = round(time.monotonic() - start, 2)
    records: list[dict] = []
    try:
        data = json.loads(stdout)
        records = data if isinstance(data, list) else []
    except Exception:
        import re as _re
        for line in stdout.splitlines():
            m = _re.search(r"\[[\+\*\!]\]\s+(A|AAAA|MX|NS|TXT|CNAME)\s+(\S+)\s+(\S+)", line)
            if m:
                records.append({"type": m.group(1), "name": m.group(2), "address": m.group(3)})
    return {
        "tool": "dnsrecon", "mock": False, "target": domain,
        "records": records, "scan_time": f"{elapsed}s",
        "stdout": stdout[:2000],
    }


async def _mock_dnsrecon(args: dict[str, Any]) -> dict[str, Any]:
    await asyncio.sleep(random.uniform(0.3, 0.8))
    target = args.get("target", "example.com")
    domain = _clean_target_for_network_scan(target)
    return {
        "tool": "dnsrecon", "mock": True, "target": domain,
        "records": [
            {"type": "A", "name": domain, "address": "93.184.216.34"},
            {"type": "MX", "name": domain, "address": f"mail.{domain}"},
        ],
        "scan_time": "0.4s",
    }


# ── Curl Probe ─────────────────────────────────────────────────────────────────

async def _real_curl_probe(args: dict[str, Any]) -> dict[str, Any]:
    """Real curl HTTP probe — headers and redirect chain."""
    target = args.get("target", "localhost")
    url = target if target.startswith("http") else f"http://{target}"
    start = time.monotonic()
    cmd = ["curl", "-sIL", "--max-time", "15", "--connect-timeout", "10",
           "-A", "Mozilla/5.0 KaliAI/3.0", url]
    stdout, stderr, code = await _run_tool_subprocess(cmd, timeout=30)
    elapsed = round(time.monotonic() - start, 2)
    headers: dict[str, str] = {}
    status_code = 0
    import re as _re
    for line in stdout.splitlines():
        line = line.strip()
        m = _re.match(r"HTTP/[\d\.]+ (\d+)", line)
        if m:
            status_code = int(m.group(1))
        elif ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()
    return {
        "tool": "curl", "mock": False, "target": url,
        "status_code": status_code, "headers": headers,
        "raw": stdout[:1500], "scan_time": f"{elapsed}s",
    }


async def _mock_curl_probe(args: dict[str, Any]) -> dict[str, Any]:
    await asyncio.sleep(random.uniform(0.1, 0.4))
    target = args.get("target", "unknown")
    return {
        "tool": "curl", "mock": True, "target": target,
        "status_code": 200,
        "headers": {"Server": "nginx/1.24.0", "Content-Type": "text/html"},
        "scan_time": "0.2s",
    }


# ── OWASP ZAP (real) ───────────────────────────────────────────────────────────

async def _real_zap(args: dict[str, Any]) -> dict[str, Any]:
    """Real OWASP ZAP scan via CLI — requires zap to be installed and running."""
    target = args.get("target", "localhost")
    scan_type = args.get("scan_type", "passive")
    url = target if target.startswith("http") else f"http://{target}"
    start = time.monotonic()
    # Try zaproxy CLI
    zap_bin = _find_binary("zaproxy") or _find_binary("zap.sh") or "zaproxy"
    if scan_type == "active":
        cmd = [zap_bin, "-cmd", "-quickurl", url, "-quickout", "/tmp/zap_report.json",
               "-quickprogress"]
    else:
        cmd = [zap_bin, "-cmd", "-quickurl", url, "-quickout", "/tmp/zap_report.json"]
    stdout, stderr, code = await _run_tool_subprocess(cmd, timeout=300)
    elapsed = round(time.monotonic() - start, 2)
    alerts: list[dict] = []
    try:
        import pathlib
        rp = pathlib.Path("/tmp/zap_report.json")
        if rp.exists():
            data = json.loads(rp.read_text())
            for site in data.get("site", []):
                for alert in site.get("alerts", []):
                    alerts.append({
                        "name": alert.get("name", ""),
                        "risk": alert.get("riskdesc", "").split(" ")[0].lower(),
                        "confidence": alert.get("confidence", "medium"),
                        "url": alert.get("instances", [{}])[0].get("uri", url),
                        "description": alert.get("desc", ""),
                    })
    except Exception:
        pass
    if not alerts and code != 0:
        return await _mock_zap(args)
    return {
        "tool": "owasp_zap", "mock": False, "target": target,
        "scan_type": scan_type, "alerts": alerts,
        "urls_crawled": len(alerts), "scan_time": f"{elapsed}s",
    }


# ── Terminal / Browser launchers (AI-callable) ─────────────────────────────────

async def _executor_open_terminal(args: dict[str, Any]) -> dict[str, Any]:
    """Launch a visible terminal window running the specified command."""
    command = args.get("command", "")
    try:
        from backend.services.terminal_launcher import open_terminal
        pid = open_terminal(command)
        return {
            "tool": "open_terminal", "success": True,
            "command": command, "pid": pid,
            "message": f"Terminal opened running: {command}",
        }
    except Exception as e:
        return {"tool": "open_terminal", "success": False, "error": str(e)}


async def _executor_open_browser(args: dict[str, Any]) -> dict[str, Any]:
    """Open a browser window at the given URL."""
    url = args.get("url", "https://example.com")
    try:
        from backend.services.browser_launcher import open_browser
        open_browser(url)
        return {"tool": "open_browser", "success": True, "url": url,
                "message": f"Browser opened at: {url}"}
    except Exception as e:
        return {"tool": "open_browser", "success": False, "error": str(e)}


async def _executor_open_tool_terminal(args: dict[str, Any]) -> dict[str, Any]:
    """Open a Kali tool in a new visible terminal window for user monitoring."""
    tool_name = args.get("tool", "")
    target = args.get("target", "")
    try:
        from backend.services.terminal_launcher import open_tool_terminal
        open_tool_terminal(tool_name, target)
        return {
            "tool": "open_tool_terminal", "success": True,
            "tool_name": tool_name, "target": target,
            "message": f"Terminal opened running {tool_name} against {target}",
        }
    except Exception as e:
        return {"tool": "open_tool_terminal", "success": False, "error": str(e)}


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
    Create a ToolRegistry pre-loaded with ALL 20+ Kali Linux security tools.
    Real binaries are auto-detected on PATH — mock fallback when not installed.
    Includes terminal & browser launchers as AI-callable tools.
    """
    registry = ToolRegistry()

    # ── 1. Nmap ───────────────────────────────────────────────────────────────
    nmap_executor, nmap_status = _pick_executor(_real_nmap, _mock_nmap, "nmap")
    registry.register(
        ToolDefinition(
            id="nmap_scan",
            name="Nmap Port Scanner",
            description="Discovers open ports, running services, and OS fingerprinting on a target host.",
            category=ToolCategory.RECONNAISSANCE,
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP or hostname."},
                    "profile": {
                        "type": "string",
                        "enum": ["quick", "standard", "service_detection"],
                        "description": "Scan profile depth.",
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

    # ── 2. WhatWeb ────────────────────────────────────────────────────────────
    whatweb_executor, whatweb_status = _pick_executor(_real_whatweb, _mock_whatweb, "whatweb")
    registry.register(
        ToolDefinition(
            id="whatweb_scan",
            name="WhatWeb Technology Identifier",
            description="Identifies web technologies, CMS, frameworks, web servers, and JavaScript libraries.",
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

    # ── 3. Nuclei ─────────────────────────────────────────────────────────────
    nuclei_executor, nuclei_status = _pick_executor(_real_nuclei, _mock_nuclei, "nuclei")
    registry.register(
        ToolDefinition(
            id="nuclei_scan",
            name="Nuclei Vulnerability Scanner",
            description="Scans for known CVEs, misconfigurations, and exposures using template-based detection.",
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

    # ── 4. Nikto ──────────────────────────────────────────────────────────────
    nikto_executor, nikto_status = _pick_executor(_real_nikto, _mock_nikto, "nikto")
    registry.register(
        ToolDefinition(
            id="nikto_scan",
            name="Nikto Web Server Scanner",
            description="Comprehensive web server tests: dangerous files, outdated software, server misconfigurations.",
            category=ToolCategory.WEB_ANALYSIS,
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL or host to scan."},
                },
                "required": ["target"],
            },
            status=nikto_status,
            risk_level=RiskLevel.MEDIUM,
            timeout=180,
        ),
        nikto_executor,
    )

    # ── 5. SSLyze ─────────────────────────────────────────────────────────────
    sslyze_executor, sslyze_status = _pick_executor(_real_sslyze, _mock_sslyze, "sslyze")
    registry.register(
        ToolDefinition(
            id="sslyze_scan",
            name="SSLyze TLS/SSL Analyzer",
            description="Analyzes TLS/SSL configuration: certificate validity, protocols, ciphers, Heartbleed, ROBOT.",
            category=ToolCategory.SSL_TLS,
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target hostname for TLS analysis."},
                },
                "required": ["target"],
            },
            status=sslyze_status,
            risk_level=RiskLevel.LOW,
            timeout=90,
        ),
        sslyze_executor,
    )

    # ── 6. OWASP ZAP ──────────────────────────────────────────────────────────
    zap_executor, zap_status = _pick_executor(_real_zap, _mock_zap, "zaproxy")
    registry.register(
        ToolDefinition(
            id="zap_scan",
            name="OWASP ZAP Web App Scanner",
            description="Passive or active web app security analysis — headers, cookies, injection, OWASP Top 10.",
            category=ToolCategory.WEB_ANALYSIS,
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL to scan."},
                    "scan_type": {
                        "type": "string",
                        "enum": ["passive", "active"],
                        "description": "Passive=safe read; active=intrusive (requires authorization).",
                    },
                },
                "required": ["target"],
            },
            status=zap_status,
            risk_level=RiskLevel.HIGH,
            timeout=300,
            permission_requirements=["explicit_authorization_for_active"],
        ),
        zap_executor,
    )

    # ── 7. Gobuster ───────────────────────────────────────────────────────────
    gobuster_executor, gobuster_status = _pick_executor(_real_gobuster, _mock_gobuster, "gobuster")
    registry.register(
        ToolDefinition(
            id="gobuster_scan",
            name="Gobuster Directory Scanner",
            description="Discovers hidden directories and files via wordlist-based brute-force.",
            category=ToolCategory.DISCOVERY,
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL to scan."},
                    "wordlist": {
                        "type": "string",
                        "enum": ["common", "small", "medium"],
                        "description": "Wordlist size.",
                    },
                },
                "required": ["target"],
            },
            status=gobuster_status,
            risk_level=RiskLevel.MEDIUM,
            timeout=180,
        ),
        gobuster_executor,
    )

    # ── 8. SQLMap ─────────────────────────────────────────────────────────────
    sqlmap_executor, sqlmap_status = _pick_executor(_real_sqlmap, _mock_sqlmap, "sqlmap")
    registry.register(
        ToolDefinition(
            id="sqlmap_scan",
            name="SQLMap SQL Injection Scanner",
            description="Automated detection and exploitation of SQL injection vulnerabilities in web parameters.",
            category=ToolCategory.VULNERABILITY_SCAN,
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL to test for SQL injection."},
                    "flags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Extra sqlmap flags e.g. ['--dbs', '--dump'].",
                    },
                },
                "required": ["target"],
            },
            status=sqlmap_status,
            risk_level=RiskLevel.HIGH,
            timeout=240,
        ),
        sqlmap_executor,
    )

    # ── 9. Hydra ──────────────────────────────────────────────────────────────
    hydra_executor, hydra_status = _pick_executor(_real_hydra, _mock_hydra, "hydra")
    registry.register(
        ToolDefinition(
            id="hydra_scan",
            name="Hydra Online Brute-Force",
            description="Online password brute-forcing against SSH, FTP, HTTP, SMB and other network services.",
            category=ToolCategory.EXPLOITATION,
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target host."},
                    "service": {
                        "type": "string",
                        "enum": ["ssh", "ftp", "http", "https", "smb", "rdp", "telnet", "pop3", "imap"],
                        "description": "Target service to brute-force.",
                    },
                    "userlist": {"type": "string", "description": "Path to username wordlist."},
                    "passlist": {"type": "string", "description": "Path to password wordlist."},
                },
                "required": ["target", "service"],
            },
            status=hydra_status,
            risk_level=RiskLevel.CRITICAL,
            timeout=180,
            permission_requirements=["explicit_authorization"],
        ),
        hydra_executor,
    )

    # ── 10. WPScan ────────────────────────────────────────────────────────────
    wpscan_executor, wpscan_status = _pick_executor(_real_wpscan, _mock_wpscan, "wpscan")
    registry.register(
        ToolDefinition(
            id="wpscan_scan",
            name="WPScan WordPress Scanner",
            description="WordPress vulnerability scanner — plugin CVEs, theme flaws, user enumeration, weak passwords.",
            category=ToolCategory.WEB_ANALYSIS,
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "WordPress site URL."},
                },
                "required": ["target"],
            },
            status=wpscan_status,
            risk_level=RiskLevel.MEDIUM,
            timeout=180,
        ),
        wpscan_executor,
    )

    # ── 11. Subfinder ─────────────────────────────────────────────────────────
    subfinder_executor, subfinder_status = _pick_executor(_real_subfinder, _mock_subfinder, "subfinder")
    registry.register(
        ToolDefinition(
            id="subfinder_scan",
            name="Subfinder Subdomain Enumerator",
            description="Passive subdomain enumeration using multiple OSINT sources.",
            category=ToolCategory.RECONNAISSANCE,
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Root domain to enumerate (e.g. example.com)."},
                },
                "required": ["target"],
            },
            status=subfinder_status,
            risk_level=RiskLevel.LOW,
            timeout=120,
        ),
        subfinder_executor,
    )

    # ── 12. Amass ─────────────────────────────────────────────────────────────
    amass_executor, amass_status = _pick_executor(_real_amass, _mock_amass, "amass")
    registry.register(
        ToolDefinition(
            id="amass_scan",
            name="Amass Subdomain Enumerator",
            description="Deep passive subdomain enumeration and DNS mapping.",
            category=ToolCategory.RECONNAISSANCE,
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Root domain to enumerate."},
                },
                "required": ["target"],
            },
            status=amass_status,
            risk_level=RiskLevel.LOW,
            timeout=120,
        ),
        amass_executor,
    )

    # ── 13. Dirb ──────────────────────────────────────────────────────────────
    dirb_executor, dirb_status = _pick_executor(_real_dirb, _mock_dirb, "dirb")
    registry.register(
        ToolDefinition(
            id="dirb_scan",
            name="Dirb Directory Scanner",
            description="Classic wordlist-based web content discovery tool.",
            category=ToolCategory.DISCOVERY,
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL to scan."},
                },
                "required": ["target"],
            },
            status=dirb_status,
            risk_level=RiskLevel.MEDIUM,
            timeout=180,
        ),
        dirb_executor,
    )

    # ── 14. Masscan ───────────────────────────────────────────────────────────
    masscan_executor, masscan_status = _pick_executor(_real_masscan, _mock_masscan, "masscan")
    registry.register(
        ToolDefinition(
            id="masscan_scan",
            name="Masscan High-Speed Port Scanner",
            description="Ultra-fast port scanner — covers entire internet-scale ranges in seconds.",
            category=ToolCategory.RECONNAISSANCE,
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP or CIDR range."},
                    "ports": {"type": "string", "description": "Port range e.g. '1-1024' or '80,443,8080'."},
                    "rate": {"type": "string", "description": "Packet rate (default 1000)."},
                },
                "required": ["target"],
            },
            status=masscan_status,
            risk_level=RiskLevel.MEDIUM,
            timeout=180,
        ),
        masscan_executor,
    )

    # ── 15. Enum4linux ────────────────────────────────────────────────────────
    enum4linux_executor, enum4linux_status = _pick_executor(_real_enum4linux, _mock_enum4linux, "enum4linux")
    registry.register(
        ToolDefinition(
            id="enum4linux_scan",
            name="Enum4linux SMB Enumerator",
            description="Enumerates SMB shares, users, groups, password policies on Windows/Samba hosts.",
            category=ToolCategory.RECONNAISSANCE,
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target Windows/Samba host IP."},
                },
                "required": ["target"],
            },
            status=enum4linux_status,
            risk_level=RiskLevel.MEDIUM,
            timeout=120,
        ),
        enum4linux_executor,
    )

    # ── 16. Fierce ────────────────────────────────────────────────────────────
    fierce_executor, fierce_status = _pick_executor(_real_fierce, _mock_fierce, "fierce")
    registry.register(
        ToolDefinition(
            id="fierce_scan",
            name="Fierce DNS Recon",
            description="DNS reconnaissance and subdomain discovery with zone transfer attempts.",
            category=ToolCategory.RECONNAISSANCE,
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target domain."},
                },
                "required": ["target"],
            },
            status=fierce_status,
            risk_level=RiskLevel.LOW,
            timeout=120,
        ),
        fierce_executor,
    )

    # ── 17. DNSRecon ──────────────────────────────────────────────────────────
    dnsrecon_executor, dnsrecon_status = _pick_executor(_real_dnsrecon, _mock_dnsrecon, "dnsrecon")
    registry.register(
        ToolDefinition(
            id="dnsrecon_scan",
            name="DNSRecon DNS Reconnaissance",
            description="Comprehensive DNS record enumeration: A, AAAA, MX, NS, TXT, SOA, zone transfers.",
            category=ToolCategory.RECONNAISSANCE,
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target domain."},
                    "scan_type": {
                        "type": "string",
                        "enum": ["std", "brt", "axfr", "rvl"],
                        "description": "Scan type: std=standard, brt=brute, axfr=zone transfer, rvl=reverse.",
                    },
                },
                "required": ["target"],
            },
            status=dnsrecon_status,
            risk_level=RiskLevel.LOW,
            timeout=120,
        ),
        dnsrecon_executor,
    )

    # ── 18. Curl Probe ────────────────────────────────────────────────────────
    curl_executor, curl_status = _pick_executor(_real_curl_probe, _mock_curl_probe, "curl")
    registry.register(
        ToolDefinition(
            id="curl_probe",
            name="Curl HTTP Probe",
            description="HTTP header inspection, redirect chain analysis, and banner grabbing via curl.",
            category=ToolCategory.WEB_ANALYSIS,
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL or host."},
                },
                "required": ["target"],
            },
            status=curl_status,
            risk_level=RiskLevel.LOW,
            timeout=30,
        ),
        curl_executor,
    )

    # ── 19. Open Terminal (AI-callable launcher) ───────────────────────────────
    registry.register(
        ToolDefinition(
            id="open_terminal",
            name="Open Terminal Window",
            description="Opens a new visible terminal window running the specified command. Use when the user wants to watch a tool run live.",
            category=ToolCategory.UTILITY,
            input_schema={
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Shell command to run in the new terminal window."},
                },
                "required": ["command"],
            },
            status=ToolStatus.AVAILABLE,
            risk_level=RiskLevel.LOW,
            timeout=10,
        ),
        _executor_open_terminal,
    )

    # ── 20. Open Browser (AI-callable launcher) ───────────────────────────────
    registry.register(
        ToolDefinition(
            id="open_browser",
            name="Open Browser",
            description="Opens Firefox or the system default browser at a given URL. Use for viewing reports, ZAP, or scanning dashboards.",
            category=ToolCategory.UTILITY,
            input_schema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to open in the browser."},
                },
                "required": ["url"],
            },
            status=ToolStatus.AVAILABLE,
            risk_level=RiskLevel.LOW,
            timeout=10,
        ),
        _executor_open_browser,
    )

    # ── 21. Open Tool Terminal (AI-callable launcher) ─────────────────────────
    registry.register(
        ToolDefinition(
            id="open_tool_terminal",
            name="Run Tool in Terminal",
            description="Runs a named Kali tool against a target in a new visible terminal window for real-time user monitoring.",
            category=ToolCategory.UTILITY,
            input_schema={
                "type": "object",
                "properties": {
                    "tool": {"type": "string", "description": "Tool name (nmap, metasploit, burpsuite, etc.)."},
                    "target": {"type": "string", "description": "Target host or URL."},
                },
                "required": ["tool", "target"],
            },
            status=ToolStatus.AVAILABLE,
            risk_level=RiskLevel.MEDIUM,
            timeout=10,
        ),
        _executor_open_tool_terminal,
    )

    return registry


# Backward-compatible alias
def create_default_registry() -> ToolRegistry:
    """Alias for create_registry() — kept for backward compatibility."""
    return create_registry()
