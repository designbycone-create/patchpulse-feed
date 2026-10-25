"""License keys, online activation, and signed feeds.

License key:      PP1-<b64url(payload)>.<b64url(sig)>     signed with the LICENSE key
Activation token: PPA1-<b64url(payload)>.<b64url(sig)>    signed with the LICENSE key by the activation server
Signed feed:      {"rules"|"intel": {...}, "signature": hex}  signed with the RULES key

The app only contains public keys, so none of these can be forged by reading the program.
There is no free tier: without a valid (and, if configured, activated) license nothing is monitored.
"""

from __future__ import annotations

import base64
import datetime as _dt
import json
import ssl
import urllib.error
import urllib.request

from . import USER_AGENT, __version__, config, ed25519

UNLIMITED = 10 ** 6
TOKEN_DAYS = 30          # activation token lifetime = offline grace period
REFRESH_WHEN_DAYS = 25   # refresh once fewer than this many days remain


class LicenseError(Exception):
    pass


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _lic_pub() -> bytes:
    return bytes.fromhex(config.PUBLIC_KEY_HEX)


def _rules_pub() -> bytes:
    return bytes.fromhex(config.RULES_PUBLIC_KEY_HEX)


def _signed(prefix: str, token: str, pub: bytes, what: str) -> dict:
    token = "".join((token or "").split())
    if not token.startswith(prefix) or "." not in token:
        raise LicenseError(f"That doesn't look like a PatchPulse {what}. It should start with {prefix}")
    body, sig = token[len(prefix):].rsplit(".", 1)
    try:
        raw, signature = _b64d(body), _b64d(sig)
    except Exception:
        raise LicenseError(f"The {what} is damaged. Copy and paste the whole thing again.")
    if not ed25519.verify(pub, raw, signature):
        raise LicenseError(f"This {what} isn't valid. Copy and paste the whole thing again.")
    return json.loads(raw)


def _sign(prefix: str, private_hex: str, payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return f"{prefix}{_b64e(raw)}.{_b64e(ed25519.sign(bytes.fromhex(private_hex.strip()), raw))}"


# ---------------- license keys

def parse_license(key: str, today: _dt.date | None = None) -> dict:
    payload = _signed("PP1-", key, _lic_pub(), "license key")
    exp = payload.get("expires")
    if exp and _dt.date.fromisoformat(exp) < (today or _dt.date.today()):
        raise LicenseError(f"This license expired on {exp}. Renew it to keep PatchPulse watching your websites.")
    plan = payload.get("plan", "personal")
    payload["sites"] = int(payload.get("sites", config.PLANS.get(plan, 5)))
    return payload


def make_license(private_hex: str, *, name: str, email: str, plan: str, sites: int | None = None,
                 expires: str | None = None, license_id: str | None = None) -> str:
    """Seller-side: create a signed license key."""
    import secrets
    payload = {"v": 1, "id": license_id or secrets.token_hex(6), "name": name, "email": email,
               "plan": plan, "sites": config.PLANS.get(plan, 5) if sites is None else int(sites),
               "issued": _dt.date.today().isoformat()}
    if expires:
        payload["expires"] = expires
    return _sign("PP1-", private_hex, payload)


def site_limit(license_payload: dict | None) -> int:
    """How many websites may be monitored. 0 = none (no license)."""
    if not license_payload:
        return 0
    n = int(license_payload.get("sites", 0))
    return UNLIMITED if n == 0 else n


# ---------------- online activation

def make_token(private_hex: str, *, license_id: str, install_id: str, days: int = TOKEN_DAYS) -> str:
    until = (_dt.date.today() + _dt.timedelta(days=days)).isoformat()
    return _sign("PPA1-", private_hex, {"lid": license_id, "iid": install_id, "until": until})


def check_token(token: str, license_id: str, install_id: str, today: _dt.date | None = None) -> dict:
    p = _signed("PPA1-", token, _lic_pub(), "activation")
    if p.get("lid") != license_id or p.get("iid") != install_id:
        raise LicenseError("This activation belongs to a different license or computer.")
    if _dt.date.fromisoformat(p["until"]) < (today or _dt.date.today()):
        raise LicenseError("PatchPulse couldn't confirm your license for 30 days. Connect to the internet and "
                           "click 'Check license now' in Settings.")
    return p


class ActivationRefused(Exception):
    def __init__(self, message: str, revoked: bool = False):
        super().__init__(message)
        self.revoked = revoked


def activate_online(url: str, key: str, install_id: str, action: str = "activate", timeout: float = 20) -> str:
    """POST to the activation server. Returns a token, or raises ActivationRefused / OSError."""
    body = json.dumps({"license_key": key, "install_id": install_id, "app_version": __version__}).encode()
    req = urllib.request.Request(url.rstrip("/") + f"/v1/{action}", data=body, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
    ctx = ssl.create_default_context()
    try:
        import certifi  # type: ignore
        ctx.load_verify_locations(certifi.where())
    except Exception:
        pass
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx if url.startswith("https") else None) as r:
            data = json.loads(r.read(64 * 1024))
    except urllib.error.HTTPError as e:
        try:
            data = json.loads(e.read(64 * 1024))
        except Exception:
            data = {}
        if 400 <= e.code < 500:
            raise ActivationRefused(data.get("error") or f"The license server refused this license ({e.code}).",
                                    revoked=bool(data.get("revoked")))
        raise OSError(f"license server error {e.code}")
    if action == "deactivate":
        return ""
    if not data.get("token"):
        raise OSError("license server sent no token")
    LAST_RESPONSE.clear()
    LAST_RESPONSE.update(data)
    return data["token"]


# The last activation response, so callers can pick up a renewed license key the server sends back.
LAST_RESPONSE: dict = {}


# ---------------- signed feeds (curated rules + hunted intel)

def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_feed(private_hex: str, kind: str, data: dict) -> dict:
    return {kind: data, "signature": ed25519.sign(bytes.fromhex(private_hex.strip()), canonical(data)).hex()}


def unwrap_feed(envelope: dict, kind: str, require_signature: bool = True) -> dict:
    if isinstance(envelope, dict) and kind in envelope and "signature" in envelope:
        try:
            sig = bytes.fromhex(envelope["signature"])
        except ValueError:
            raise LicenseError("feed signature is malformed")
        if not ed25519.verify(_rules_pub(), canonical(envelope[kind]), sig):
            raise LicenseError("feed signature does not match - update rejected")
        return envelope[kind]
    if require_signature:
        raise LicenseError("feed is not signed - update rejected")
    return envelope


# backwards-compatible names
def sign_rules(private_hex: str, rules: dict) -> dict:
    return sign_feed(private_hex, "rules", rules)


def unwrap_rules(envelope: dict, require_signature: bool = True) -> dict:
    return unwrap_feed(envelope, "rules", require_signature)
