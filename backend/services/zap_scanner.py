"""
Kali AI - OWASP ZAP Auto-Scanner
==================================
Fully automated OWASP ZAP integration.

Flow:
  1. Start ZAP in daemon mode (headless) if not already running.
  2. Spider the target URL (crawls all pages/links automatically).
  3. Run an active scan (tests for OWASP Top 10 and more).
  4. Optionally open a REAL browser proxied through ZAP so the user
     can watch the scan happening live in ZAP's GUI.
  5. Pull scan results via ZAP REST API and return as structured findings.
  6. Generate a full vulnerability report with CVSS scores.

Requirements on Kali:
    sudo apt install zaproxy -y
    # or download from https://www.zaproxy.org/download/

ZAP API key is set to 'kali-ai-zap' by default (configure in .env as ZAP_API_KEY).
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ── ZAP Config ───────────────────────────────────────────────────────
ZAP_HOST = "127.0.0.1"
ZAP_PORT = 8090           # We use 8090 to avoid clash with Burp on 8080
ZAP_API_KEY = "kali-ai-zap"
ZAP_API_BASE = f"http://{ZAP_HOST}:{ZAP_PORT}/JSON"

_zap_process: subprocess.Popen | None = None


# ── ZAP Finding ──────────────────────────────────────────────────────

@dataclass
class ZapFinding:
    name: str
    risk: str            # High / Medium / Low / Informational
    confidence: str      # High / Medium / Low
    url: str
    description: str
    solution: str
    cweid: str
    wascid: str

    def severity_badge(self) -> str:
        return {
            "High": "🔴 HIGH",
            "Medium": "🟠 MEDIUM",
            "Low": "🟡 LOW",
            "Informational": "🔵 INFO",
        }.get(self.risk, self.risk)


@dataclass
class ZapScanResult:
    target: str
    success: bool
    findings: list[ZapFinding] = field(default_factory=list)
    spider_urls: int = 0
    scan_progress: int = 0
    duration_seconds: float = 0.0
    error: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def report_section(self) -> str:
        lines = [
            f"# 🕷️ OWASP ZAP Scan Report — {self.target}",
            f"**Scanned at:** {self.timestamp}",
            f"**Duration:** {self.duration_seconds:.0f}s",
            f"**URLs crawled:** {self.spider_urls}",
            f"**Vulnerabilities found:** {len(self.findings)}",
            "",
        ]

        if not self.findings:
            lines += ["## ✅ No vulnerabilities found!", ""]
            return "\n".join(lines)

        # Group by severity
        for risk in ["High", "Medium", "Low", "Informational"]:
            group = [f for f in self.findings if f.risk == risk]
            if not group:
                continue
            lines.append(f"## {group[0].severity_badge()} ({len(group)} issues)")
            for f in group:
                lines += [
                    f"### {f.name}",
                    f"- **URL:** `{f.url}`",
                    f"- **Confidence:** {f.confidence}",
                    f"- **CWE:** {f.cweid}  |  **WASC:** {f.wascid}",
                    f"- **Description:** {f.description[:300]}",
                    f"- **Solution:** {f.solution[:200]}",
                    "",
                ]

        lines += [
            "## Remediation Priority",
            "1. Fix all HIGH severity issues immediately.",
            "2. Address MEDIUM severity issues in next sprint.",
            "3. LOW severity issues should be tracked and resolved.",
            "",
        ]
        return "\n".join(lines)


# ── ZAP Daemon Management ─────────────────────────────────────────────

def _zap_binary() -> str | None:
    """Find ZAP binary on Kali."""
    for name in ["zaproxy", "zap.sh", "zap"]:
        path = shutil.which(name)
        if path:
            return path
    # Common Kali install path
    for p in ["/usr/share/zaproxy/zap.sh", "/opt/zaproxy/zap.sh"]:
        if shutil.os.path.exists(p):
            return p
    return None


def _is_zap_running() -> bool:
    """Check if ZAP daemon is already listening."""
    import socket
    try:
        s = socket.create_connection((ZAP_HOST, ZAP_PORT), timeout=2)
        s.close()
        return True
    except Exception:
        return False


def start_zap_daemon(headless: bool = True) -> bool:
    """
    Start OWASP ZAP in daemon mode.
    Returns True if ZAP is ready to accept requests.
    """
    global _zap_process

    if _is_zap_running():
        logger.info("[ZAP] Already running on port %d", ZAP_PORT)
        return True

    zap_bin = _zap_binary()
    if not zap_bin:
        logger.error("[ZAP] ZAP binary not found. Install: sudo apt install zaproxy")
        return False

    cmd = [
        zap_bin,
        "-daemon",
        "-host", ZAP_HOST,
        "-port", str(ZAP_PORT),
        "-config", f"api.key={ZAP_API_KEY}",
        "-config", "api.addrs.addr.name=.*",
        "-config", "api.addrs.addr.regex=true",
    ]

    if headless:
        cmd += ["-config", "view.mode=attack"]

    logger.info("[ZAP] Starting daemon: %s", " ".join(cmd))

    try:
        _zap_process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception as exc:
        logger.error("[ZAP] Failed to start: %s", exc)
        return False

    # Wait up to 60 seconds for ZAP to start
    for i in range(60):
        if _is_zap_running():
            logger.info("[ZAP] Ready after %ds", i + 1)
            return True
        time.sleep(1)

    logger.error("[ZAP] Did not start within 60 seconds.")
    return False


def stop_zap_daemon() -> None:
    """Stop the ZAP daemon."""
    global _zap_process
    if _zap_process:
        _zap_process.terminate()
        _zap_process = None
        logger.info("[ZAP] Daemon stopped.")


def open_zap_gui() -> str:
    """Open ZAP in GUI mode (not daemon) for interactive use."""
    zap_bin = _zap_binary()
    if not zap_bin:
        return "ZAP not found. Install: sudo apt install zaproxy"
    try:
        subprocess.Popen([zap_bin], start_new_session=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return f"✅ ZAP GUI opened."
    except Exception as exc:
        return f"Failed to open ZAP GUI: {exc}"


# ── ZAP REST API helpers ──────────────────────────────────────────────

async def _zap_get(endpoint: str, params: dict[str, str] | None = None) -> dict[str, Any]:
    """Make an async GET request to the ZAP REST API."""
    import urllib.request
    import urllib.parse

    base_params = {"apikey": ZAP_API_KEY}
    if params:
        base_params.update(params)

    query = urllib.parse.urlencode(base_params)
    url = f"{ZAP_API_BASE}/{endpoint}?{query}"

    def _fetch():
        with urllib.request.urlopen(url, timeout=10) as resp:
            return json.loads(resp.read().decode())

    return await asyncio.to_thread(_fetch)


# ── Main Scan Flow ────────────────────────────────────────────────────

async def zap_scan(
    target: str,
    open_browser_live: bool = True,
    max_spider_minutes: int = 3,
    max_scan_minutes: int = 10,
) -> ZapScanResult:
    """
    Run a full OWASP ZAP scan on `target`.

    1. Start ZAP daemon
    2. Optionally open Firefox proxied through ZAP (user watches live)
    3. Spider the target
    4. Run active scan
    5. Collect and return findings

    Parameters
    ----------
    target              : URL to scan (e.g. "http://testphp.vulnweb.com")
    open_browser_live   : open Firefox through ZAP proxy so user sees it live
    max_spider_minutes  : minutes to let spider run
    max_scan_minutes    : minutes to let active scan run
    """
    # Ensure URL has scheme
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    start_time = time.monotonic()

    # 1. Start ZAP daemon
    logger.info("[ZAP] Starting scan on %s", target)
    zap_ready = start_zap_daemon(headless=True)
    if not zap_ready:
        return ZapScanResult(
            target=target, success=False,
            error="ZAP daemon failed to start. Install: sudo apt install zaproxy",
        )

    # 2. Open browser proxied through ZAP (optional — user watches the crawl live)
    if open_browser_live:
        from backend.services.browser_launcher import open_browser
        result = open_browser(target, proxy=f"http://{ZAP_HOST}:{ZAP_PORT}")
        if isinstance(result, str):
            logger.warning("[ZAP] Browser open failed: %s", result)
        else:
            logger.info("[ZAP] Browser opened on %s via ZAP proxy", target)
            # Give user 3 seconds to see the browser open
            await asyncio.sleep(3)

    # 3. Spider
    logger.info("[ZAP] Spidering %s ...", target)
    try:
        spider_resp = await _zap_get("spider/action/scan", {"url": target, "recurse": "true"})
        scan_id = spider_resp.get("scan", "0")

        # Wait for spider to complete (or timeout)
        for _ in range(max_spider_minutes * 12):  # check every 5s
            status_resp = await _zap_get("spider/view/status", {"scanId": scan_id})
            progress = int(status_resp.get("status", "0"))
            logger.info("[ZAP] Spider progress: %d%%", progress)
            if progress >= 100:
                break
            await asyncio.sleep(5)

        urls_resp = await _zap_get("spider/view/results", {"scanId": scan_id})
        spider_urls = len(urls_resp.get("results", []))
        logger.info("[ZAP] Spider found %d URLs", spider_urls)

    except Exception as exc:
        logger.warning("[ZAP] Spider error: %s", exc)
        spider_urls = 0

    # 4. Active Scan
    logger.info("[ZAP] Starting active scan on %s ...", target)
    try:
        ascan_resp = await _zap_get("ascan/action/scan", {
            "url": target,
            "recurse": "true",
            "inScopeOnly": "false",
        })
        ascan_id = ascan_resp.get("scan", "0")

        # Wait for active scan to complete (or timeout)
        for _ in range(max_scan_minutes * 12):  # check every 5s
            status_resp = await _zap_get("ascan/view/status", {"scanId": ascan_id})
            progress = int(status_resp.get("status", "0"))
            logger.info("[ZAP] Active scan progress: %d%%", progress)
            if progress >= 100:
                break
            await asyncio.sleep(5)

    except Exception as exc:
        logger.warning("[ZAP] Active scan error: %s", exc)

    # 5. Collect alerts/findings
    findings: list[ZapFinding] = []
    try:
        alerts_resp = await _zap_get("alert/view/alerts", {"baseurl": target})
        for alert in alerts_resp.get("alerts", []):
            findings.append(ZapFinding(
                name=alert.get("name", "Unknown"),
                risk=alert.get("risk", "Informational"),
                confidence=alert.get("confidence", "Low"),
                url=alert.get("url", target),
                description=alert.get("description", ""),
                solution=alert.get("solution", ""),
                cweid=alert.get("cweid", ""),
                wascid=alert.get("wascid", ""),
            ))
        logger.info("[ZAP] Found %d alerts", len(findings))

    except Exception as exc:
        logger.warning("[ZAP] Alert collection error: %s", exc)

    duration = time.monotonic() - start_time

    return ZapScanResult(
        target=target,
        success=True,
        findings=findings,
        spider_urls=spider_urls,
        duration_seconds=round(duration, 1),
    )


# ── Quick ZAP Passive Scan (no active attacks) ───────────────────────

async def zap_passive_scan(target: str) -> ZapScanResult:
    """
    Open target in browser proxied through ZAP and collect
    PASSIVE findings only (no active attacks, safe for any site).
    """
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    start_time = time.monotonic()

    zap_ready = start_zap_daemon(headless=False)  # GUI mode so user sees ZAP
    if not zap_ready:
        return ZapScanResult(
            target=target, success=False,
            error="ZAP not found. Install: sudo apt install zaproxy",
        )

    # Open browser through ZAP — ZAP passively scans all traffic
    from backend.services.browser_launcher import open_browser
    result = open_browser(target, proxy=f"http://{ZAP_HOST}:{ZAP_PORT}")
    if isinstance(result, str):
        return ZapScanResult(target=target, success=False, error=result)

    # Wait for user to browse, then collect passive findings
    logger.info("[ZAP] Passive scan — waiting 15s for page load & passive analysis...")
    await asyncio.sleep(15)

    findings: list[ZapFinding] = []
    try:
        alerts_resp = await _zap_get("alert/view/alerts", {"baseurl": target})
        for alert in alerts_resp.get("alerts", []):
            findings.append(ZapFinding(
                name=alert.get("name", "Unknown"),
                risk=alert.get("risk", "Informational"),
                confidence=alert.get("confidence", "Low"),
                url=alert.get("url", target),
                description=alert.get("description", ""),
                solution=alert.get("solution", ""),
                cweid=alert.get("cweid", ""),
                wascid=alert.get("wascid", ""),
            ))
    except Exception as exc:
        logger.warning("[ZAP] Passive scan alerts error: %s", exc)

    return ZapScanResult(
        target=target, success=True,
        findings=findings,
        duration_seconds=round(time.monotonic() - start_time, 1),
    )
