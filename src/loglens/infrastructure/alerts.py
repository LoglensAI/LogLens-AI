from __future__ import annotations

import ipaddress
import json
import logging
import os
import smtplib
import threading
import time
import urllib.request
from email.mime.text import MIMEText
from pathlib import Path
from typing import Protocol, runtime_checkable
from urllib.parse import urlparse

from loglens.domain.models import Anomaly
from loglens.domain.severity import CARD_COLOR_DEFAULT, CARD_COLORS, EMOJI, EMOJI_DEFAULT

logger = logging.getLogger("loglens.infrastructure.alerts")


@runtime_checkable
class Alerter(Protocol):
    name: str

    def send(self, app: str, a: Anomaly, rca_line: str | None = None) -> None: ...


def _post_json(url: str, payload: dict, timeout: int) -> None:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=timeout).read()


# Hosts that are never legitimate webhook targets — classic SSRF pivots.
_BLOCKED_HOSTS = {"169.254.169.254", "metadata.google.internal", "metadata"}


def validate_webhook_url(url: str) -> str:
    """Validate a webhook URL and return it, guarding against SSRF.

    Rejects non-http(s) schemes and cloud metadata / link-local endpoints
    outright. Private/loopback hosts are allowed (self-hosted Slack/Mattermost
    are common) but logged, so a misconfiguration is at least visible.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Webhook URL must use http(s), got '{parsed.scheme or 'no scheme'}'")
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("Webhook URL has no host")
    if host in _BLOCKED_HOSTS:
        raise ValueError(f"Refusing to post alerts to metadata endpoint '{host}'")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.is_link_local:
            raise ValueError(f"Refusing to post alerts to link-local address '{host}'")
        if ip.is_private or ip.is_loopback:
            logger.warning(
                "webhook host %s is private/loopback; allowed but verify it is intended", host
            )
    return url


def load_dotenv(path: str = ".env") -> None:
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip().strip("'\"")
        if k and k not in os.environ:
            os.environ[k] = v


def _fmt_text(app: str, a: Anomaly, rca_line: str | None) -> str:
    emoji = EMOJI.get(a.level.upper(), EMOJI_DEFAULT)
    svc = f" · {a.service}" if a.service not in ("", "unknown") else ""
    lines = [f"{emoji} [{app}] {a.level}{svc} (score {a.score:.2f})", a.message]
    if rca_line:
        lines.append(f"↳ likely cause: {rca_line}")
    if a.timestamp:
        lines.append(f"at {a.timestamp}")
    return "\n".join(lines)


class SlackAlerter:
    name = "slack"

    def __init__(self, webhook_url: str, timeout: int = 10):
        self.url = validate_webhook_url(webhook_url)
        self.timeout = timeout

    def send(self, app: str, a: Anomaly, rca_line: str | None = None) -> None:
        _post_json(self.url, {"text": _fmt_text(app, a, rca_line)}, self.timeout)


class TeamsAlerter:
    name = "teams"

    def __init__(self, webhook_url: str, timeout: int = 10):
        self.url = validate_webhook_url(webhook_url)
        self.timeout = timeout

    def send(self, app: str, a: Anomaly, rca_line: str | None = None) -> None:
        facts = [{"name": "Level", "value": a.level}, {"name": "Score", "value": f"{a.score:.2f}"}]
        if a.service not in ("", "unknown"):
            facts.append({"name": "Service", "value": a.service})
        if a.timestamp:
            facts.append({"name": "When", "value": a.timestamp})
        if rca_line:
            facts.append({"name": "Likely cause", "value": rca_line})
        card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": CARD_COLORS.get(a.level.upper(), CARD_COLOR_DEFAULT),
            "summary": f"[{app}] {a.level}: {a.message[:80]}",
            "sections": [
                {
                    "activityTitle": f"🚨 LogLens alert — {app}",
                    "activitySubtitle": a.message,
                    "facts": facts,
                }
            ],
        }
        _post_json(self.url, card, self.timeout)


class EmailAlerter:
    name = "email"

    def __init__(
        self,
        host: str,
        port: int,
        user: str,
        password: str,
        to: list[str],
        sender: str = "",
        use_tls: bool = True,
        timeout: int = 15,
    ):
        self.host, self.port = host, port
        self.user, self.password = user, password
        self.to = to
        self.sender = sender or user
        self.use_tls = use_tls
        self.timeout = timeout
        if not use_tls and password:
            logger.warning(
                "EmailAlerter configured without TLS (use_tls=False); SMTP "
                "credentials will be sent in cleartext."
            )

    def send(self, app: str, a: Anomaly, rca_line: str | None = None) -> None:
        msg = MIMEText(_fmt_text(app, a, rca_line))
        msg["Subject"] = f"[LogLens] {app}: {a.level} — {a.message[:70]}"
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.to)
        with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as s:
            if self.use_tls:
                s.starttls()
            if self.user:
                s.login(self.user, self.password)
            s.sendmail(self.sender, self.to, msg.as_string())


def alerters_from_env(dotenv: str = ".env") -> list:
    load_dotenv(dotenv)
    out: list = []
    slack = os.getenv("LOGLENS_SLACK_WEBHOOK", "").strip()
    if slack:
        out.append(SlackAlerter(slack))
    teams = os.getenv("LOGLENS_TEAMS_WEBHOOK", "").strip()
    if teams:
        out.append(TeamsAlerter(teams))
    host = os.getenv("LOGLENS_EMAIL_SMTP_HOST", "").strip()
    to = [t.strip() for t in os.getenv("LOGLENS_EMAIL_TO", "").split(",") if t.strip()]
    if host and to:
        out.append(
            EmailAlerter(
                host=host,
                port=int(os.getenv("LOGLENS_EMAIL_SMTP_PORT", "587")),
                user=os.getenv("LOGLENS_EMAIL_USER", ""),
                password=os.getenv("LOGLENS_EMAIL_PASSWORD", ""),
                to=to,
                sender=os.getenv("LOGLENS_EMAIL_FROM", ""),
            )
        )
    return out


class AlertDispatcher:
    def __init__(
        self, alerters: list, *, app: str = "app", cooldown: float = 300.0, max_per_hour: int = 30
    ):
        self.alerters = alerters
        self.app = app
        self.cooldown = cooldown
        self.max_per_hour = max_per_hour
        self._last_sent: dict[str, float] = {}
        self._hour_stamps: list[float] = []
        self.sent = 0
        self.suppressed = 0
        self.errors = 0
        # Guards the rate-limit state + counters; dispatch() is called from the
        # monitor's worker thread and (on crash) the main-thread excepthook.
        self._lock = threading.Lock()

    @staticmethod
    def _key(a: Anomaly) -> str:
        import re

        masked = re.sub(r"(?<!\S)\S*\d\S*", "<id>", a.message.lower())
        return f"{a.level.upper()}|{a.service}|{masked[:120]}"

    def _allowed(self, a: Anomaly) -> bool:
        now = time.time()
        self._hour_stamps = [t for t in self._hour_stamps if now - t < 3600]
        if len(self._hour_stamps) >= self.max_per_hour:
            return False
        key = self._key(a)
        if now - self._last_sent.get(key, 0.0) < self.cooldown:
            return False
        self._last_sent[key] = now
        self._hour_stamps.append(now)
        return True

    def dispatch(self, a: Anomaly, rca_line: str | None = None) -> bool:
        with self._lock:
            allowed = bool(self.alerters) and self._allowed(a)
            if not allowed:
                self.suppressed += 1
        if not allowed:
            return False
        # Network I/O happens outside the lock so a slow webhook can't block
        # the rate-limit bookkeeping.
        ok = False
        for al in self.alerters:
            try:
                al.send(self.app, a, rca_line)
                ok = True
            except Exception as exc:
                # One alerter failing must not stop the others; count and log.
                with self._lock:
                    self.errors += 1
                logger.warning(
                    "alerter %s failed: %s: %s",
                    type(al).__name__,
                    type(exc).__name__,
                    exc,
                )
        if ok:
            with self._lock:
                self.sent += 1
        return ok

    def stats(self) -> dict[str, object]:
        return {
            "sent": self.sent,
            "suppressed": self.suppressed,
            "errors": self.errors,
            "channels": [al.name for al in self.alerters],
        }
