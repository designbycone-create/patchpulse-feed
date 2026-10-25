"""Alert delivery: phone push (ntfy), email (SMTP), chat webhooks (Slack/Discord/Teams/any)."""

from __future__ import annotations

import json
import smtplib
import ssl
import urllib.request
from email.message import EmailMessage
from urllib.parse import urlsplit

from . import APP_NAME, USER_AGENT
from .netsafe import make_ssl_context

DEFAULT_ALERTS = {
    "min_severity": "high",
    "notify_resolved": True,
    "ntfy": {"enabled": False, "server": "https://ntfy.sh", "topic": ""},
    "email": {"enabled": False, "smtp_host": "", "smtp_port": 587, "security": "starttls",
              "username": "", "password": "", "from_addr": "", "to_addr": ""},
    "webhook": {"enabled": False, "url": ""},
}

SECRET_FIELDS = {("email", "password")}


def merged(cfg: dict | None) -> dict:
    out = json.loads(json.dumps(DEFAULT_ALERTS))
    for k, v in (cfg or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k].update(v)
        else:
            out[k] = v
    return out


def masked(cfg: dict) -> dict:
    c = json.loads(json.dumps(merged(cfg)))
    for sec, field in SECRET_FIELDS:
        if c[sec].get(field):
            c[sec][field] = "********"
    return c


def _post_json(url: str, payload: dict, timeout: float = 10.0):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout, context=make_ssl_context()) as r:
        r.read(4096)
        return r.status


PRIORITY = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 2, "resolved": 3}


def send_ntfy(c: dict, title: str, message: str, level: str, click: str | None = None):
    server = (c.get("server") or "https://ntfy.sh").rstrip("/")
    topic = (c.get("topic") or "").strip()
    if not topic:
        raise ValueError("Phone alerts need a topic name.")
    if not server.startswith(("https://", "http://")):
        raise ValueError("ntfy server must start with https://")
    payload = {"topic": topic, "title": title[:250], "message": message[:3800],
               "priority": PRIORITY.get(level, 3),
               "tags": ["rotating_light"] if level == "critical" else
                       ["white_check_mark"] if level == "resolved" else ["warning"]}
    if click:
        payload["click"] = click
    _post_json(server, payload)


def send_email(c: dict, title: str, message: str, level: str, click: str | None = None):
    for f in ("smtp_host", "from_addr", "to_addr"):
        if not c.get(f):
            raise ValueError("Email alerts need the mail server, the 'from' address and the 'to' address.")
    msg = EmailMessage()
    msg["Subject"] = f"[{APP_NAME}] {title}"
    msg["From"] = c["from_addr"]
    msg["To"] = c["to_addr"]
    body = message + (f"\n\nOpen {APP_NAME}: {click}" if click else "") + \
        f"\n\n-- \nSent by {APP_NAME}. You can change alert settings in the app under 'Alerts'."
    msg.set_content(body)
    port = int(c.get("smtp_port") or 587)
    sec = c.get("security", "starttls")
    ctx = ssl.create_default_context()
    if sec == "ssl":
        server = smtplib.SMTP_SSL(c["smtp_host"], port, timeout=20, context=ctx)
    else:
        server = smtplib.SMTP(c["smtp_host"], port, timeout=20)
    try:
        if sec == "starttls":
            server.starttls(context=ctx)
        if c.get("username"):
            server.login(c["username"], c.get("password", ""))
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except Exception:
            pass


def send_webhook(c: dict, title: str, message: str, level: str, click: str | None = None,
                 extra: dict | None = None):
    url = (c.get("url") or "").strip()
    if not url.startswith(("https://", "http://")):
        raise ValueError("Webhook address must start with https://")
    host = urlsplit(url).hostname or ""
    icon = {"critical": "\U0001F6A8", "resolved": "✅"}.get(level, "⚠️")
    text = f"{icon} *{title}*\n{message}" + (f"\n{click}" if click else "")
    if "discord" in host:
        payload = {"content": text.replace("*", "**")[:1990]}
    elif "hooks.slack.com" in host:
        payload = {"text": text}
    elif "office.com" in host or "webhook.office" in host or "logic.azure.com" in host:
        payload = {"text": text.replace("\n", "<br>")}
    else:
        payload = {"app": APP_NAME.lower(), "title": title, "message": message, "level": level,
                   "url": click, **(extra or {})}
    _post_json(url, payload)


CHANNELS = {"ntfy": send_ntfy, "email": send_email, "webhook": send_webhook}


def send_all(cfg: dict, title: str, message: str, level: str, click: str | None = None,
             extra: dict | None = None, only: str | None = None) -> list[dict]:
    """Send to every enabled channel (or just `only`). Never raises."""
    cfg = merged(cfg)
    results = []
    for name, fn in CHANNELS.items():
        ch = cfg.get(name) or {}
        if only and name != only:
            continue
        if not only and not ch.get("enabled"):
            continue
        try:
            if name == "webhook":
                fn(ch, title, message, level, click, extra)
            else:
                fn(ch, title, message, level, click)
            results.append({"channel": name, "ok": True})
        except Exception as e:
            results.append({"channel": name, "ok": False, "error": _friendly(e)})
    return results


def _friendly(e: Exception) -> str:
    s = str(e) or e.__class__.__name__
    if isinstance(e, smtplib.SMTPAuthenticationError):
        return ("The email server rejected the username/password. For Gmail you must use an "
                "'App Password', not your normal password.")
    if isinstance(e, (TimeoutError,)) or "timed out" in s:
        return "The server took too long to answer. Check the address and port."
    if "Name or service not known" in s or "getaddrinfo" in s or "nodename" in s:
        return "Couldn't find that server address. Check the spelling."
    if "HTTP Error 4" in s:
        return f"The service refused the message ({s}). Check the address/topic."
    return s[:300]
