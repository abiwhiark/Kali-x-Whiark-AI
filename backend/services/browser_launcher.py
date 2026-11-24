"""
Kali AI - Browser Launcher
============================
Opens a real browser (Firefox, Chromium) on behalf of Kali AI.
Can:
  - Open any URL in Firefox / Chromium
  - Open a URL with a proxy set (routes through OWASP ZAP or Burp Suite)
  - Open a URL in a private/incognito window
  - Open the OWASP ZAP browser (pre-configured with ZAP proxy)
  - Open Burp Suite's embedded browser
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


# ── Browser preference order ─────────────────────────────────────────
BROWSERS = [
    "firefox",
    "firefox-esr",
    "chromium",
    "chromium-browser",
    "google-chrome",
    "brave-browser",
    "epiphany",
]


def _find_browser() -> str | None:
    """Return the first available browser on this system."""
    for b in BROWSERS:
        if shutil.which(b):
            return b
    return None


@dataclass
class BrowserSession:
    """Represents an opened browser window."""
    session_id: str
    browser: str
    url: str
    proxy: str | None = None
    private: bool = False
    opened_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    pid: int = -1

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "browser": self.browser,
            "url": self.url,
            "proxy": self.proxy,
            "private": self.private,
            "opened_at": self.opened_at,
            "pid": self.pid,
        }


_browser_sessions: dict[str, BrowserSession] = {}


def open_browser(
    url: str,
    proxy: str | None = None,
    private: bool = False,
    browser: str | None = None,
) -> BrowserSession | str:
    """
    Open a browser window navigating to `url`.

    Parameters
    ----------
    url     : URL to open (e.g. "https://testphp.vulnweb.com")
    proxy   : optional HTTP proxy (e.g. "http://127.0.0.1:8080" for ZAP/Burp)
    private : open in private/incognito mode
    browser : force a specific browser binary name
    """
    b = browser or _find_browser()
    if b is None:
        return (
            "No browser found. Install one with:\n"
            "  sudo apt install firefox-esr\n"
            "  or: sudo apt install chromium"
        )

    # Ensure URL has a scheme
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    cmd: list[str] = [b]

    # Private mode flag
    if private:
        if "firefox" in b:
            cmd.append("--private-window")
        elif "chromium" in b or "chrome" in b or "brave" in b:
            cmd.append("--incognito")

    # Proxy settings
    if proxy:
        if "firefox" in b:
            # Firefox needs a profile or env var for proxy; use env approach
            # We'll pass proxy as an argument via marionette or just use --new-instance
            # For simplicity, open with proxy env vars set
            import os
            os.environ["http_proxy"] = proxy
            os.environ["https_proxy"] = proxy
            os.environ["HTTP_PROXY"] = proxy
            os.environ["HTTPS_PROXY"] = proxy
            logger.info("[BrowserLauncher] Set proxy env vars to %s for Firefox", proxy)
        elif "chromium" in b or "chrome" in b or "brave" in b:
            cmd += [f"--proxy-server={proxy}"]

    cmd.append(url)

    logger.info("[BrowserLauncher] Opening: %s", " ".join(cmd))

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        session_id = f"browser_{int(time.time() * 1000)}"
        session = BrowserSession(
            session_id=session_id,
            browser=b,
            url=url,
            proxy=proxy,
            private=private,
            pid=proc.pid,
        )
        _browser_sessions[session_id] = session
        logger.info("[BrowserLauncher] Opened %s → %s (pid=%d)", b, url, proc.pid)
        return session

    except Exception as exc:
        logger.error("[BrowserLauncher] Failed: %s", exc)
        return f"Failed to open browser: {exc}"


def open_browser_with_zap_proxy(url: str) -> BrowserSession | str:
    """
    Open a browser with OWASP ZAP proxy (127.0.0.1:8080).
    Traffic is intercepted and scanned by ZAP automatically.
    """
    return open_browser(url, proxy="http://127.0.0.1:8080")


def open_browser_with_burp_proxy(url: str) -> BrowserSession | str:
    """
    Open a browser with Burp Suite proxy (127.0.0.1:8080 by default).
    """
    return open_browser(url, proxy="http://127.0.0.1:8080")


def list_browser_sessions() -> list[dict[str, Any]]:
    """List all opened browser sessions this run."""
    return [s.to_dict() for s in _browser_sessions.values()]
