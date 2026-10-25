"""Web app + REST API (standard library only).

Security model
  * One owner password (PBKDF2-SHA256, 310k rounds), session cookie
    (HttpOnly, SameSite=Strict), 30-day sessions.
  * API tokens for automation: `Authorization: Bearer <token>`.
  * Cookie-authenticated writes must carry `X-PatchPulse: 1`, which
    cross-site pages cannot send -> CSRF protection.
  * Host-header allow-list when bound to localhost -> DNS-rebinding protection.
  * Login rate limiting, strict Content-Security-Policy, no inline script.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import mimetypes
import os
import re
import secrets
import threading
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import APP_NAME, __version__, alerts as alerts_mod, config, licensing, netsafe
from .engine import Engine
from .rules import SEVERITIES
from .store import Store

log = logging.getLogger("patchpulse")
WEB = Path(__file__).parent / "web"
mimetypes.add_type("font/woff2", ".woff2")
mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("text/css", ".css")
mimetypes.add_type("image/svg+xml", ".svg")
DATA = Path(__file__).parent / "data"
SESSION_TTL = 30 * 86400
PBKDF2_ROUNDS = 310_000
MAX_BODY = 64 * 1024
PROVIDERS = json.loads((DATA / "guides.json").read_text("utf-8"))["providers"].keys()

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


class ApiError(Exception):
    def __init__(self, status: int, message: str, code: str = "error"):
        super().__init__(message)
        self.status, self.message, self.code = status, message, code


def hash_password(pw: str, salt: bytes | None = None) -> dict:
    salt = salt or secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ROUNDS)
    return {"salt": salt.hex(), "hash": h.hex(), "rounds": PBKDF2_ROUNDS}


def check_password(pw: str, rec: dict) -> bool:
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(rec["salt"]), int(rec["rounds"]))
    return hmac.compare_digest(h.hex(), rec["hash"])


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


class App:
    def __init__(self, data_dir: Path, host: str, port: int):
        self.data_dir = Path(data_dir)
        self.store = Store(self.data_dir / "patchpulse.db")
        self.engine = Engine(self.store)
        self.host, self.port = host, port
        self._login_fails: dict[str, list[float]] = {}
        self._lock = threading.Lock()
        allowed = os.environ.get("PATCHPULSE_ALLOWED_HOSTS", "")
        self.allowed_hosts = {h.strip().lower() for h in allowed.split(",") if h.strip()}
        self.loopback_only = host in ("127.0.0.1", "localhost", "::1")
        if not self.store.get("public_url"):
            shown = "localhost" if self.loopback_only or host in ("0.0.0.0", "::") else host
            self.store.set("public_url", f"http://{shown}:{port}")

    # ----- rate limit -----
    def login_blocked(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            fails = [t for t in self._login_fails.get(ip, []) if now - t < 600]
            self._login_fails[ip] = fails
            return len(fails) >= 10

    def login_failed(self, ip: str):
        with self._lock:
            self._login_fails.setdefault(ip, []).append(time.time())


def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"{APP_NAME}/{__version__}"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            log.debug("%s - %s", self.address_string(), fmt % args)

        # ---------- plumbing ----------
        def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store" if ctype.startswith("application/json") else "no-cache")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status: int, obj, extra: dict | None = None):
            self._send(status, json.dumps(obj).encode(), "application/json; charset=utf-8", extra)

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                raise ApiError(413, "Request too large")
            if n == 0:
                return {}
            try:
                data = json.loads(self.rfile.read(n).decode("utf-8"))
            except ValueError:
                raise ApiError(400, "Invalid JSON")
            if not isinstance(data, dict):
                raise ApiError(400, "Expected a JSON object")
            return data

        def _cookie_token(self) -> str | None:
            c = SimpleCookie(self.headers.get("Cookie", ""))
            return c["pp_session"].value if "pp_session" in c else None

        def _auth(self) -> str | None:
            """Returns 'session', 'token' or None."""
            authz = self.headers.get("Authorization", "")
            if authz.startswith("Bearer "):
                tok = authz[7:].strip()
                stored = app.store.get("api_token_hash")
                if stored and hmac.compare_digest(_sha(tok), stored):
                    return "token"
                return None
            tok = self._cookie_token()
            if tok and app.store.session_valid(_sha(tok)):
                return "session"
            return None

        def _host_ok(self) -> bool:
            host = (self.headers.get("Host") or "").lower()
            name = re.sub(r":\d+$", "", host).strip("[]")
            if app.allowed_hosts:
                return name in app.allowed_hosts or name in ("localhost", "127.0.0.1", "::1")
            if app.loopback_only:
                return name in ("localhost", "127.0.0.1", "::1")
            return True

        def _dispatch(self, method: str):
            try:
                if not self._host_ok():
                    return self._send(403, b"Host not allowed", "text/plain")
                path = urlsplit(self.path).path
                if path.startswith("/api/"):
                    return self._api(method, path)
                if method not in ("GET", "HEAD"):
                    raise ApiError(405, "Method not allowed")
                return self._static(path)
            except ApiError as e:
                self._json(e.status, {"error": e.message, "code": e.code})
            except Exception:
                log.exception("request failed")
                self._json(500, {"error": "Something went wrong inside PatchPulse. Please try again."})

        def do_GET(self): self._dispatch("GET")
        def do_HEAD(self): self._dispatch("HEAD")
        def do_POST(self): self._dispatch("POST")
        def do_PUT(self): self._dispatch("PUT")
        def do_PATCH(self): self._dispatch("PATCH")
        def do_DELETE(self): self._dispatch("DELETE")

        def _static(self, path: str):
            if path in ("", "/"):
                path = "/index.html"
            target = (WEB / path.lstrip("/")).resolve()
            if WEB.resolve() not in target.parents or not target.is_file():
                target = WEB / "index.html"  # single-page app fallback
            ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype in ("application/javascript", "image/svg+xml"):
                ctype += "; charset=utf-8"
            self._send(200, target.read_bytes(), ctype)

        # ---------- API ----------
        def _api(self, method: str, path: str):
            open_routes = {("GET", "/api/health"), ("GET", "/api/status"), ("POST", "/api/setup"),
                           ("POST", "/api/login"), ("POST", "/api/logout")}
            kind = None
            if (method, path) not in open_routes:
                kind = self._auth()
                if not kind:
                    raise ApiError(401, "Please sign in.", "auth")
                if kind == "session" and method not in ("GET", "HEAD") and self.headers.get("X-PatchPulse") != "1":
                    raise ApiError(403, "Missing X-PatchPulse header", "csrf")
            if method in ("POST", "PUT", "PATCH") and (method, path) != ("POST", "/api/logout"):
                ctype = self.headers.get("Content-Type", "")
                if self.headers.get("Content-Length", "0") != "0" and "application/json" not in ctype:
                    raise ApiError(415, "Send JSON (Content-Type: application/json)")
            for (m, pattern), fn in ROUTES:
                if m == method:
                    mm = re.fullmatch(pattern, path)
                    if mm:
                        return fn(self, *[int(g) for g in mm.groups()])
            raise ApiError(404, "Not found")

        # open
        def r_health(self):
            self._json(200, {"ok": True, "version": __version__})

        def r_status(self):
            needs_setup = not app.store.get("auth")
            signed_in = bool(self._auth())
            out = {"app": APP_NAME, "version": __version__, "setup_needed": needs_setup,
                   "signed_in": signed_in, "buy_url": config.BUY_URL, "support_email": config.SUPPORT_EMAIL}
            if signed_in:
                ls = app.engine.license_status()
                out["license_state"], out["license_message"] = ls["state"], ls["message"]
            self._json(200, out)

        def r_setup(self):
            if app.store.get("auth"):
                raise ApiError(409, "PatchPulse is already set up. Please sign in.")
            pw = str(self._body().get("password", ""))
            if len(pw) < 8:
                raise ApiError(400, "Please choose a password with at least 8 characters.")
            app.store.set("auth", hash_password(pw))
            app.store.event("system", "PatchPulse was set up")
            self._new_session()

        def r_login(self):
            ip = self.client_address[0]
            if app.login_blocked(ip):
                raise ApiError(429, "Too many wrong passwords. Please wait 10 minutes and try again.")
            rec = app.store.get("auth")
            if not rec:
                raise ApiError(409, "Please finish setup first.", "setup")
            pw = str(self._body().get("password", ""))
            if not check_password(pw, rec):
                app.login_failed(ip)
                raise ApiError(401, "That password isn't right. Please try again.", "bad_password")
            self._new_session()

        def _new_session(self):
            tok = secrets.token_urlsafe(32)
            app.store.add_session(_sha(tok), SESSION_TTL)
            secure = "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else ""
            self._json(200, {"ok": True}, {
                "Set-Cookie": f"pp_session={tok}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}{secure}"})

        def r_logout(self):
            tok = self._cookie_token()
            if tok:
                app.store.drop_session(_sha(tok))
            self._json(200, {"ok": True}, {"Set-Cookie": "pp_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"})

        # sites
        def _site_summary(self, s: dict, active_ids: set) -> dict:
            scan = app.store.latest_scan(s["id"])
            top = None
            counts = {}
            if scan:
                active = [f for f in scan.get("findings", []) if f["key"] not in s["dismissed"]]
                for f in active:
                    counts[f["severity"]] = counts.get(f["severity"], 0) + 1
                if active:
                    top = {"title": active[0]["title"], "severity": active[0]["severity"]}
            return {"id": s["id"], "url": s["url"], "label": s["label"], "provider": s["provider"],
                    "status": s["last_status"], "last_scan_at": s["last_scan_at"], "scanning": s["scanning"],
                    "top": top, "counts": counts, "active": s["id"] in active_ids,
                    "php_version": (scan or {}).get("facts", {}).get("php_version"),
                    "error": (scan or {}).get("error")}

        def _require_license(self):
            ls = app.engine.license_status()
            if ls["state"] != "active":
                raise ApiError(402, ls["message"] or "Activate your license to start monitoring.", "license")

        def r_list_sites(self):
            active_ids = {s["id"] for s in app.engine.active_sites()}
            sites = [self._site_summary(s, active_ids) for s in app.store.sites()]
            ls = app.engine.license_status()
            limit = app.engine.site_limit()
            self._json(200, {"sites": sites, "limit": None if limit >= licensing.UNLIMITED else limit,
                             "plan": ((ls["license"] or {}).get("plan") if ls["state"] == "active" else None),
                             "license_state": ls["state"], "license_message": ls["message"],
                             "intel": app.engine.intel_summary(),
                             "rules_version": app.engine.rules["rules_version"],
                             "advisories": [{"id": a["id"], "name": a.get("name", a["id"]),
                                             "severity": a["severity"], "published": a.get("published")}
                                            for a in app.engine.rules.get("advisories", [])]})

        def r_add_site(self):
            b = self._body()
            if not b.get("confirm_owner"):
                raise ApiError(400, "Please tick the box to confirm you own or manage this website.")
            try:
                url = netsafe.normalize_site_url(str(b.get("url", "")))
            except ValueError as e:
                raise ApiError(400, str(e))
            if any(s["url"] == url for s in app.store.sites()):
                raise ApiError(409, "That website is already on your list.")
            self._require_license()
            if not app.engine.can_add_site():
                limit = app.engine.site_limit()
                raise ApiError(402, f"Your plan covers {limit} website{'s' if limit != 1 else ''}. "
                                    "Upgrade your plan to watch more.", "limit")
            provider = str(b.get("provider") or "unsure")
            if provider not in PROVIDERS:
                provider = "unsure"
            label = str(b.get("label") or "").strip()[:80]
            sid = app.store.add_site(url, label, provider)
            app.store.event("site", f"Added {url}", sid)
            app.engine.scan_async(sid, "added")
            self._json(201, {"id": sid, "url": url})

        def r_get_site(self, sid: int):
            v = app.engine.view(sid)
            if not v:
                raise ApiError(404, "Website not found")
            v["site"]["active"] = app.engine.is_active(sid)
            v["site"]["protect"] = app.store.get(f"protect:{sid}", {}) or {}
            v["site"].pop("check_token", None)
            self._json(200, v)

        def r_patch_site(self, sid: int):
            s = app.store.site(sid)
            if not s:
                raise ApiError(404, "Website not found")
            b = self._body()
            upd = {}
            if "label" in b:
                upd["label"] = str(b["label"]).strip()[:80]
            if "provider" in b:
                upd["provider"] = b["provider"] if b["provider"] in PROVIDERS else "unsure"
            if "dismiss" in b or "undismiss" in b:
                d = set(s["dismissed"])
                if b.get("dismiss"):
                    d.add(str(b["dismiss"])[:120])
                if b.get("undismiss"):
                    d.discard(str(b["undismiss"]))
                upd["dismissed"] = sorted(d)
                # don't send a "fixed" alert for something the owner chose to ignore
                upd["alerted_keys"] = [k for k in s["alerted_keys"] if k not in d]
            if isinstance(b.get("protect"), dict):
                cur = app.store.get(f"protect:{sid}", {}) or {}
                for k, val in list(b["protect"].items())[:20]:
                    if re.fullmatch(r"[a-z0-9-]{1,40}", str(k)):
                        cur[str(k)] = bool(val)
                app.store.set(f"protect:{sid}", cur)
            app.store.update_site(sid, **upd)
            if "dismissed" in upd:
                scan = app.store.latest_scan(sid)
                if scan:
                    status = app.engine._effective_status(scan, upd["dismissed"])
                    app.store.update_site(sid, last_status=status)
            self.r_get_site(sid)

        def r_delete_site(self, sid: int):
            s = app.store.site(sid)
            if not s:
                raise ApiError(404, "Website not found")
            app.store.delete_site(sid)
            app.store.set(f"protect:{sid}", None)
            app.store.event("site", f"Removed {s['url']}")
            self._json(200, {"ok": True})

        def r_scan_site(self, sid: int):
            if not app.store.site(sid):
                raise ApiError(404, "Website not found")
            self._require_license()
            if not app.engine.is_active(sid):
                raise ApiError(402, "This website isn't covered by your current plan.", "limit")
            started = app.engine.scan_async(sid, "manual")
            self._json(202, {"ok": True, "started": started})

        def r_scan_all(self):
            self._require_license()
            self._json(202, {"ok": True, "started": app.engine.scan_all("manual")})

        def r_check_file(self, sid: int):
            s = app.store.site(sid)
            if not s:
                raise ApiError(404, "Website not found")
            php = (DATA / "patchpulse-check.php").read_text("utf-8")
            php = php.replace("__PATCHPULSE_KEY__", s["check_token"])
            self._send(200, php.encode(), "application/octet-stream", {
                "Content-Disposition": 'attachment; filename="patchpulse-check.php"'})

        def r_rotate_check_key(self, sid: int):
            if not app.store.site(sid):
                raise ApiError(404, "Website not found")
            app.store.update_site(sid, check_token=secrets.token_urlsafe(24))
            self._json(200, {"ok": True})

        # settings
        def r_get_settings(self):
            st = app.store.all_settings()
            ls = app.engine.license_status()
            lic = ls["license"]
            limit = app.engine.site_limit()
            self._json(200, {
                "scan_interval_hours": app.engine.interval_hours,
                "hunt_minutes": app.engine.hunt_minutes,
                "has_nvd_key": bool(st.get("nvd_api_key")),
                "intel": app.engine.intel_summary(),
                "license_state": ls["state"], "license_message": ls["message"],
                "online_activation": bool(app.engine.activation_url),
                "allow_private": bool(st.get("allow_private", False)),
                "rules_url": st.get("rules_url", config.RULES_URL) or "",
                "public_url": st.get("public_url", ""),
                "alerts": alerts_mod.masked(st.get("alerts")),
                "has_api_token": bool(st.get("api_token_hash")),
                "rules_version": app.engine.rules["rules_version"],
                "rules_updated": app.engine.rules.get("updated"),
                "rules_checked_at": st.get("rules_checked_at"),
                "license": ({k: lic.get(k) for k in ("name", "email", "plan", "sites", "expires", "id",
                                                     "activated_until")} if lic else None),
                "site_limit": None if limit >= licensing.UNLIMITED else limit,
                "version": __version__, "data_dir": str(app.data_dir),
                "severities": SEVERITIES,
            })

        def r_put_settings(self):
            b = self._body()
            if "scan_interval_hours" in b:
                try:
                    v = float(b["scan_interval_hours"])
                except (TypeError, ValueError):
                    raise ApiError(400, "Check frequency must be a number of hours.")
                app.store.set("scan_interval_hours", min(168.0, max(0.25, v)))
            if "allow_private" in b:
                app.store.set("allow_private", bool(b["allow_private"]))
            if "rules_url" in b:
                u = str(b["rules_url"] or "").strip()
                if u and not u.startswith("https://"):
                    raise ApiError(400, "The update address must start with https://")
                app.store.set("rules_url", u)
            if "public_url" in b:
                app.store.set("public_url", str(b["public_url"] or "").strip()[:200])
            if "hunt_minutes" in b:
                try:
                    app.store.set("hunt_minutes", min(1440.0, max(15.0, float(b["hunt_minutes"]))))
                except (TypeError, ValueError):
                    raise ApiError(400, "Threat hunt frequency must be a number of minutes.")
            if "nvd_api_key" in b:
                k = str(b["nvd_api_key"] or "").strip()
                if k != "********":
                    if k and not re.fullmatch(r"[A-Za-z0-9-]{20,64}", k):
                        raise ApiError(400, "That doesn't look like an NVD API key.")
                    app.store.set("nvd_api_key", k)
            if "alerts" in b and isinstance(b["alerts"], dict):
                cur = alerts_mod.merged(app.store.get("alerts"))
                new = alerts_mod.merged(b["alerts"])
                for sec, field in alerts_mod.SECRET_FIELDS:  # keep stored secret if masked placeholder sent
                    if new[sec].get(field) == "********":
                        new[sec][field] = cur[sec].get(field, "")
                if new.get("min_severity") not in SEVERITIES:
                    new["min_severity"] = "high"
                app.store.set("alerts", new)
            self.r_get_settings()

        def r_test_alert(self):
            b = self._body()
            channel = b.get("channel")
            if channel not in alerts_mod.CHANNELS:
                raise ApiError(400, "Unknown alert type")
            cfg = alerts_mod.merged(app.store.get("alerts"))
            res = alerts_mod.send_all(cfg, "Test alert - it works!",
                                      "This is a test from PatchPulse. If you can read this, alerts are set up "
                                      "correctly. You'll get a message like this if a website needs attention.",
                                      "info", app.store.get("public_url") or None, only=channel)
            self._json(200, res[0] if res else {"ok": False, "error": "Not configured"})

        def r_new_token(self):
            tok = "ppk_" + secrets.token_urlsafe(32)
            app.store.set("api_token_hash", _sha(tok))
            app.store.event("system", "A new API key was created")
            self._json(200, {"token": tok})

        def r_revoke_token(self):
            app.store.set("api_token_hash", None)
            self._json(200, {"ok": True})

        def r_change_password(self):
            b = self._body()
            if not check_password(str(b.get("current", "")), app.store.get("auth")):
                raise ApiError(400, "Your current password isn't right.")
            new = str(b.get("new", ""))
            if len(new) < 8:
                raise ApiError(400, "Please choose a new password with at least 8 characters.")
            app.store.set("auth", hash_password(new))
            app.store.drop_all_sessions()
            self._new_session()

        def r_set_license(self):
            key = str(self._body().get("key", "")).strip()
            if not key:
                raise ApiError(400, "Paste your license key first.")
            try:
                app.engine.set_license(key)
            except licensing.LicenseError as e:
                raise ApiError(400, str(e))
            app.engine.scan_all("license")
            app.engine.hunt_async()
            self.r_get_settings()

        def r_remove_license(self):
            app.engine.remove_license()
            self.r_get_settings()

        def r_refresh_license(self):
            app.engine.refresh_license(force=True)
            self.r_get_settings()

        def r_intel(self):
            self._json(200, app.engine.intel_summary())

        def r_hunt(self):
            self._require_license()
            started = app.engine.hunt_async()
            self._json(202, {"ok": True, "started": started})

        def r_update_rules(self):
            try:
                res = app.engine.update_rules(rescan=True)
            except Exception as e:
                raise ApiError(502, f"Couldn't get the latest threat list: {e}")
            self._json(200, res)

        def r_guides(self):
            self._send(200, (DATA / "guides.json").read_bytes(), "application/json; charset=utf-8")

        def r_events(self):
            self._json(200, {"events": app.store.events(100)})

        def r_export(self):
            out = {"exported_at": time.time(), "version": __version__, "sites": []}
            for s in app.store.sites():
                v = app.engine.view(s["id"])
                v["site"].pop("check_token", None)
                out["sites"].append(v)
            self._send(200, json.dumps(out, indent=2).encode(), "application/json; charset=utf-8",
                       {"Content-Disposition": 'attachment; filename="patchpulse-export.json"'})

        def r_quick_check(self):
            """Synchronous one-off scan without saving (for scripts)."""
            b = self._body()
            try:
                url = netsafe.normalize_site_url(str(b.get("url", "")))
            except ValueError as e:
                raise ApiError(400, str(e))
            self._require_license()
            from .scanner import scan_site
            try:
                res = scan_site(url, app.engine.rules, allow_private=app.engine.allow_private,
                                intel=app.engine.intel)
            except netsafe.UnsafeTarget as e:
                raise ApiError(400, str(e))
            self._json(200, {"url": url, **res})

    ROUTES = [
        (("GET", r"/api/health"), Handler.r_health),
        (("GET", r"/api/status"), Handler.r_status),
        (("POST", r"/api/setup"), Handler.r_setup),
        (("POST", r"/api/login"), Handler.r_login),
        (("POST", r"/api/logout"), Handler.r_logout),
        (("GET", r"/api/sites"), Handler.r_list_sites),
        (("POST", r"/api/sites"), Handler.r_add_site),
        (("POST", r"/api/sites/scan"), Handler.r_scan_all),
        (("GET", r"/api/sites/(\d+)"), Handler.r_get_site),
        (("PATCH", r"/api/sites/(\d+)"), Handler.r_patch_site),
        (("DELETE", r"/api/sites/(\d+)"), Handler.r_delete_site),
        (("POST", r"/api/sites/(\d+)/scan"), Handler.r_scan_site),
        (("GET", r"/api/sites/(\d+)/checkfile"), Handler.r_check_file),
        (("POST", r"/api/sites/(\d+)/checkfile/rotate"), Handler.r_rotate_check_key),
        (("GET", r"/api/settings"), Handler.r_get_settings),
        (("PUT", r"/api/settings"), Handler.r_put_settings),
        (("POST", r"/api/alerts/test"), Handler.r_test_alert),
        (("POST", r"/api/token"), Handler.r_new_token),
        (("DELETE", r"/api/token"), Handler.r_revoke_token),
        (("POST", r"/api/password"), Handler.r_change_password),
        (("POST", r"/api/license"), Handler.r_set_license),
        (("DELETE", r"/api/license"), Handler.r_remove_license),
        (("POST", r"/api/license/refresh"), Handler.r_refresh_license),
        (("GET", r"/api/intel"), Handler.r_intel),
        (("POST", r"/api/intel/hunt"), Handler.r_hunt),
        (("POST", r"/api/rules/update"), Handler.r_update_rules),
        (("GET", r"/api/guides"), Handler.r_guides),
        (("GET", r"/api/events"), Handler.r_events),
        (("GET", r"/api/export"), Handler.r_export),
        (("POST", r"/api/check"), Handler.r_quick_check),
    ]
    return Handler


def _already_running(port: int) -> bool:
    import urllib.request
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f"http://127.0.0.1:{port}/api/status", timeout=1.5) as r:
            return json.loads(r.read(4096)).get("app") == APP_NAME
    except Exception:
        return False


def find_free_port(host: str, start: int) -> int:
    import socket
    for port in range(start, start + 20):
        with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET) as s:
            try:
                s.bind((host, port))
                return port
            except OSError:
                continue
    raise OSError(f"No free port found near {start}")


def serve(data_dir: Path, host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True,
          start_scheduler: bool = True):
    # Already running? Just open it instead of starting a second copy.
    if host in ("127.0.0.1", "localhost") and _already_running(port):
        url = f"http://localhost:{port}"
        print(f"\n  {APP_NAME} is already running at {url} - opening it in your browser.\n", flush=True)
        if open_browser:
            import webbrowser
            webbrowser.open(url)
        return None
    port = find_free_port(host, port)
    app = App(data_dir, host, port)
    httpd = ThreadingHTTPServer((host, port), make_handler(app))
    httpd.daemon_threads = True
    if start_scheduler:
        app.engine.start()
    url = f"http://{'localhost' if host in ('127.0.0.1', '0.0.0.0', '::', '::1') else host}:{port}"
    print(f"\n  {APP_NAME} {__version__} is running.\n  Open this address in your web browser:  {url}\n"
          f"  (Keep this window open. Close it to stop {APP_NAME}.)\n", flush=True)
    if open_browser:
        import webbrowser
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.engine.stop()
        httpd.server_close()
    return app
