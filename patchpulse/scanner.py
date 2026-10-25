"""Outside-in website checks.

Everything here is what any visitor's browser could see: normal page
requests, security headers, the certificate, and whether well-known
sensitive files are accidentally public. Nothing is attacked or exploited.
"""

from __future__ import annotations

import concurrent.futures as cf
import datetime as _dt
import json
import re
import ssl
import threading
import time
import urllib.request
from urllib.parse import urlsplit

from . import USER_AGENT
from . import netsafe
from .assess import assess
from .rules import SEV_RANK, parse_version, sort_findings

_WP_CACHE = {"at": 0.0, "value": None}
_WP_LOCK = threading.Lock()
WP_VERSION_API = "https://api.wordpress.org/core/version-check/1.7/"


def wordpress_latest(timeout: float = 8.0) -> str | None:
    """Latest WordPress release from wordpress.org (cached 6 hours)."""
    with _WP_LOCK:
        if _WP_CACHE["value"] and time.time() - _WP_CACHE["at"] < 6 * 3600:
            return _WP_CACHE["value"]
    try:
        req = urllib.request.Request(WP_VERSION_API, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout, context=netsafe.make_ssl_context()) as r:
            data = json.loads(r.read(256 * 1024).decode("utf-8"))
        latest = data["offers"][0]["current"]
        if parse_version(latest):
            with _WP_LOCK:
                _WP_CACHE.update(at=time.time(), value=latest)
            return latest
    except Exception:
        pass
    return _WP_CACHE["value"]


# ---- sensitive file probes: (path, validator, severity, title, detail, fix) ----

def _looks_env(b: bytes) -> bool:
    t = b[:8192].decode("utf-8", "replace")
    if "<html" in t.lower():
        return False
    return len(re.findall(r"(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*=", t)) >= 2


def _looks_git(b: bytes) -> bool:
    return b[:64].startswith(b"ref: refs/") or bool(re.fullmatch(rb"[0-9a-f]{40}\s*", b[:64]))


def _looks_wpconfig(b: bytes) -> bool:
    return b"DB_PASSWORD" in b and b"<html" not in b[:2048].lower()


def _looks_phpinfo(b: bytes) -> bool:
    return b"phpinfo()" in b or (b"PHP Version" in b and b"PHP License" in b)


def _looks_sql(b: bytes) -> bool:
    head = b[:65536]
    return (b"CREATE TABLE" in head or b"INSERT INTO" in head) and b"<html" not in head[:2048].lower()


def _looks_debuglog(b: bytes) -> bool:
    return bool(re.search(rb"PHP (Fatal error|Warning|Notice|Deprecated)", b[:65536])) and b"<html" not in b[:2048].lower()


_SECRET_FIX = ("Delete this file from your website, or ask your hosting company to block it. "
               "Then change every password it contains (database, email, payment keys) - "
               "assume someone has already copied them.")

PROBES = [
    ("/.env", _looks_env, "critical", "Your private settings file (.env) is public",
     "Anyone can download a file that usually holds database passwords and secret keys.", _SECRET_FIX),
    ("/.git/HEAD", _looks_git, "critical", "Your website's source code history (.git) is public",
     "Attackers can download your site's code and any passwords saved in it.",
     "Remove the .git folder from the public website folder, or block it. Then change any passwords in your code."),
    ("/wp-config.php.bak", _looks_wpconfig, "critical", "A backup of your WordPress settings is public",
     "This copy of wp-config holds your database password and anyone can read it.", _SECRET_FIX),
    ("/wp-config.php~", _looks_wpconfig, "critical", "A backup of your WordPress settings is public",
     "This copy of wp-config holds your database password and anyone can read it.", _SECRET_FIX),
    ("/wp-config.php.save", _looks_wpconfig, "critical", "A backup of your WordPress settings is public",
     "This copy of wp-config holds your database password and anyone can read it.", _SECRET_FIX),
    ("/wp-config.old", _looks_wpconfig, "critical", "A backup of your WordPress settings is public",
     "This copy of wp-config holds your database password and anyone can read it.", _SECRET_FIX),
    ("/wp-config.txt", _looks_wpconfig, "critical", "A backup of your WordPress settings is public",
     "This copy of wp-config holds your database password and anyone can read it.", _SECRET_FIX),
    ("/backup.sql", _looks_sql, "critical", "A database backup is public",
     "Anyone can download a copy of your database, which may include customer details and passwords.", _SECRET_FIX),
    ("/dump.sql", _looks_sql, "critical", "A database backup is public",
     "Anyone can download a copy of your database, which may include customer details and passwords.", _SECRET_FIX),
    ("/database.sql", _looks_sql, "critical", "A database backup is public",
     "Anyone can download a copy of your database, which may include customer details and passwords.", _SECRET_FIX),
    ("/phpinfo.php", _looks_phpinfo, "high", "A server details page (phpinfo) is public",
     "This test page shows attackers exactly how your server is set up, including versions to target.",
     "Delete phpinfo.php from your website. It is only meant for temporary testing."),
    ("/info.php", _looks_phpinfo, "high", "A server details page (phpinfo) is public",
     "This test page shows attackers exactly how your server is set up, including versions to target.",
     "Delete info.php from your website. It is only meant for temporary testing."),
    ("/wp-content/debug.log", _looks_debuglog, "medium", "Your WordPress error log is public",
     "Error logs can reveal file locations, plugin names and sometimes private data.",
     "Delete wp-content/debug.log and turn off WP_DEBUG_LOG in wp-config.php (or ask your host/developer)."),
]


def _finding(key, severity, title, detail, fix, *, category="site", guide=None,
             support_ask="", references=None, evidence=""):
    return {"key": key, "severity": severity, "category": category, "title": title,
            "detail": detail, "fix": fix, "guide": guide, "support_ask": support_ask,
            "references": references or [], "evidence": evidence}


def _probe(base: str, path: str, allow_private: bool, verify: bool):
    try:
        r = netsafe.fetch(base + path, allow_private=allow_private, verify_tls=verify,
                          follow_redirects=False, timeout=8, max_body=128 * 1024)
        return path, r
    except Exception:
        return path, None


def _wp_version_from_html(html: str) -> str | None:
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([\d.]+)', html, re.I)
    if not m:
        m = re.search(r'content=["\']WordPress\s+([\d.]+)["\'][^>]+name=["\']generator', html, re.I)
    return m.group(1) if m else None


def scan_site(base_url: str, rules: dict, *, allow_private: bool = False,
              check_token: str | None = None, check_wp_latest: bool = True,
              today: _dt.date | None = None, intel: dict | None = None) -> dict:
    """Run every check against one site. Never raises; errors become findings."""
    started = time.time()
    base = netsafe.normalize_site_url(base_url)
    parts = urlsplit(base)
    host = parts.hostname
    port = parts.port
    findings: list[dict] = []
    facts: dict = {"checked_url": base}
    verify = True

    # 1. Reach the homepage (prefer HTTPS)
    home = None
    http_base = f"http://{parts.netloc}"
    first_error = None
    candidates = [f"https://{parts.netloc}"] if parts.scheme == "https" else [http_base]
    for cand in candidates:
        try:
            home = netsafe.fetch(cand + "/", allow_private=allow_private, verify_tls=True)
            base = cand
            break
        except ssl.SSLCertVerificationError as e:
            msg = getattr(e, "verify_message", "") or "the certificate could not be verified"
            findings.append(_finding(
                "tls:invalid", "critical", "Your security certificate (the padlock) is broken",
                f"Browsers will show visitors a scary warning page and many will leave. Reason: {msg}.",
                "Renew or reinstall your SSL certificate. Most hosts offer free automatic certificates "
                "(often called 'Let's Encrypt' or 'Free SSL') in the control panel.",
                category="https", guide="ssl", support_ask="Please fix or renew the SSL certificate on my website."))
            verify = False
            try:
                home = netsafe.fetch(cand + "/", allow_private=allow_private, verify_tls=False)
                base = cand
                break
            except Exception as e2:
                first_error = first_error or e2
        except netsafe.UnsafeTarget:
            raise
        except Exception as e:
            first_error = first_error or e
    if home is None and parts.scheme == "https":
        # HTTPS dead - is the site up on plain HTTP?
        try:
            home = netsafe.fetch(http_base + "/", allow_private=allow_private, follow_redirects=False)
            base = http_base
            findings.append(_finding(
                "https:missing", "high", "Your website doesn't have a working secure (https) connection",
                "Visitors' passwords and form details travel unprotected, and browsers mark the site 'Not secure'.",
                "Turn on a free SSL certificate in your hosting control panel (often called 'SSL' or 'Let's Encrypt').",
                category="https", guide="ssl", support_ask="Please enable a free SSL certificate (https) for my website."))
        except Exception:
            pass
    if home is None:
        reason = str(first_error) if first_error else "no answer"
        findings.append(_finding(
            "site:down", "critical", "We couldn't reach your website",
            f"Your website did not load when we checked. {reason}",
            "Open your website in a browser. If it's down for you too, contact your hosting company. "
            "If it works for you, it may have been a short hiccup - we'll check again automatically.",
            category="uptime", guide="down", support_ask="My website isn't loading. Can you check what's wrong?"))
        return _result("down", findings, facts, started)

    facts.update({
        "final_url": home.url, "http_status": home.status,
        "response_ms": int(home.elapsed * 1000), "https": base.startswith("https"),
        "tls_version": home.tls_version, "server": home.header("server")[:120],
    })
    if home.status >= 500:
        findings.append(_finding(
            "site:error", "high", f"Your website is showing a server error ({home.status})",
            "Visitors are seeing an error page instead of your site.",
            "Contact your hosting company or developer. Recent plugin/theme updates are a common cause.",
            category="uptime", guide="down", support_ask=f"My website is returning error {home.status}. Can you help?"))

    html = home.text()
    if home.url.startswith("https://") and not base.startswith("https"):
        base = "https://" + urlsplit(home.url).netloc
        facts["https"] = True

    # 1b. Site entered as http:// - does a secure version exist at all?
    if not facts.get("https") and not any(f["key"] == "https:missing" for f in findings):
        try:
            netsafe.fetch(f"https://{urlsplit(base).hostname}/", allow_private=allow_private,
                          follow_redirects=False, timeout=6, max_body=1024)
            findings.append(_finding(
                "https:no-redirect", "medium", "Visitors can still land on the unsecured version of your site",
                "Your site has a secure (https) version, but the plain address doesn't switch visitors to it.",
                "Turn on 'Force HTTPS' (sometimes called 'HTTPS redirect') in your hosting control panel.",
                category="https", guide="ssl", support_ask="Please turn on 'Force HTTPS' redirect for my website."))
        except ssl.SSLCertVerificationError:
            findings.append(_finding(
                "tls:invalid", "critical", "Your security certificate (the padlock) is broken",
                "The secure version of your site shows visitors a warning page.",
                "Renew or reinstall your SSL certificate (often called 'Let's Encrypt' or 'Free SSL').",
                category="https", guide="ssl", support_ask="Please fix or renew the SSL certificate on my website."))
        except netsafe.UnsafeTarget:
            raise
        except Exception:
            findings.append(_finding(
                "https:missing", "high", "Your website doesn't have a working secure (https) connection",
                "Visitors' passwords and form details travel unprotected, and browsers mark the site 'Not secure'.",
                "Turn on a free SSL certificate in your hosting control panel (often called 'SSL' or 'Let's Encrypt').",
                category="https", guide="ssl", support_ask="Please enable a free SSL certificate (https) for my website."))

    # 2. HTTP -> HTTPS redirect
    if facts.get("https") and not port:
        try:
            plain = netsafe.fetch(f"http://{host}/", allow_private=allow_private, follow_redirects=False, timeout=8)
            loc = plain.header("location")
            if not (plain.status in (301, 302, 307, 308) and loc.startswith("https://")):
                findings.append(_finding(
                    "https:no-redirect", "medium", "Visitors can still land on the unsecured version of your site",
                    "Typing your address without https:// opens an unprotected page instead of switching to the secure one.",
                    "Turn on 'Force HTTPS' (sometimes called 'HTTPS redirect') in your hosting control panel.",
                    category="https", guide="ssl", support_ask="Please turn on 'Force HTTPS' redirect for my website."))
        except Exception:
            pass

    # 3. Certificate expiry
    if facts.get("https"):
        try:
            cert = netsafe.get_certificate(urlsplit(base).hostname, port or 443, allow_private)
            facts["cert_issuer"] = cert.get("issuer", "")
            if cert.get("not_after"):
                days = int((cert["not_after"] - time.time()) // 86400)
                facts["cert_days_left"] = days
                if days < 0:
                    if not any(f["key"] == "tls:invalid" for f in findings):
                        findings.append(_finding(
                            "tls:expired", "critical", "Your security certificate has expired",
                            f"It expired {-days} day(s) ago. Visitors see a warning page.",
                            "Renew the SSL certificate in your hosting control panel.",
                            category="https", guide="ssl", support_ask="My SSL certificate has expired. Please renew it."))
                elif days <= 14:
                    findings.append(_finding(
                        "tls:expiring", "high", f"Your security certificate expires in {days} day(s)",
                        "When it expires, visitors will see a warning page and many will leave.",
                        "Renew it now, or switch on automatic renewal in your hosting control panel.",
                        category="https", guide="ssl", support_ask="My SSL certificate expires soon. Please renew it or enable auto-renewal."))
                elif days <= 30:
                    findings.append(_finding(
                        "tls:expiring", "medium", f"Your security certificate expires in {days} days",
                        "Most certificates renew automatically, but it's worth confirming.",
                        "Check that auto-renewal is on in your hosting control panel.",
                        category="https", guide="ssl"))
        except Exception:
            pass

    # 4. Software versions: PHP
    php_version, php_source = None, None
    xpb = home.header("x-powered-by")
    m = re.search(r"PHP/([\d.]+[\w.+~-]*)", xpb, re.I)
    if m:
        php_version, php_source = m.group(1), "the website's response headers"

    # 4b. Optional check file (exact version, works even when hidden)
    facts["check_file"] = "not set up"
    if check_token:
        try:
            r = netsafe.fetch(base + "/patchpulse-check.php", allow_private=allow_private, verify_tls=verify,
                              headers={"X-PatchPulse-Token": check_token}, follow_redirects=False, timeout=8,
                              max_body=4096)
            if r.status == 200:
                data = json.loads(r.text())
                if data.get("app") == "patchpulse" and parse_version(data.get("php_version")):
                    php_version, php_source = str(data["php_version"])[:40], "your PatchPulse check file"
                    facts["check_file"] = "working"
                    facts["php_sapi"] = str(data.get("sapi", ""))[:40]
                    facts["upload_progress"] = bool(data.get("upload_progress"))
                else:
                    facts["check_file"] = "not recognized"
            elif r.status == 403:
                facts["check_file"] = "wrong key - download the file again"
            else:
                facts["check_file"] = "not found on website"
        except Exception:
            facts["check_file"] = "could not read"

    # 5. Sensitive file probes (in parallel)
    wp_detected = bool(re.search(r"/wp-(content|includes)/", html)) or "WordPress" in (
        _wp_version_from_html(html) or "")
    paths = [p[0] for p in PROBES]
    if wp_detected:
        paths.append("/wp-content/uploads/")
    probe_results = {}
    with cf.ThreadPoolExecutor(max_workers=6) as ex:
        for path, r in ex.map(lambda p: _probe(base, p, allow_private, verify), paths):
            probe_results[path] = r
    seen_titles = set()
    for path, validator, sev, title, detail, fix in PROBES:
        r = probe_results.get(path)
        if r is not None and r.status == 200 and validator(r.body):
            if title in seen_titles:
                continue
            seen_titles.add(title)
            findings.append(_finding(
                f"exposed:{path}", sev, title, f"{detail}\n\nFound at: {base}{path}", fix,
                category="exposure", guide="exposed_file", evidence=path,
                support_ask=f"Please remove or block public access to {path} on my website."))
            if validator is _looks_phpinfo and not php_version:
                mv = re.search(rb"PHP Version\s*(?:</[^>]+>\s*<[^>]+>\s*)?([\d.]+[\w.+~-]*)", r.body)
                if mv:
                    php_version, php_source = mv.group(1).decode()[:40], f"the public {path} page"
    ul = probe_results.get("/wp-content/uploads/")
    if ul is not None and ul.status == 200 and b"Index of" in ul.body[:4096]:
        findings.append(_finding(
            "exposed:dirlist", "medium", "Anyone can browse a list of all your uploaded files",
            "Your uploads folder shows a full file list, which can expose private documents and invoices.",
            "Turn off 'directory listing' (often called 'Indexes') in your hosting control panel, "
            "or ask your host to do it.",
            category="exposure", guide="exposed_file",
            support_ask="Please turn off directory listing (Indexes) for my website's wp-content/uploads folder."))

    # 6. Software inventory (everything we can identify, with versions)
    facts["php_version"] = php_version
    facts["php_source"] = php_source
    inventory: list[dict] = []
    if php_version:
        inventory.append({"product": "php", "version": php_version, "source": php_source,
                          "distro": bool(re.search(r"(ubuntu|deb|el\d|fc\d|\+)", php_version, re.I))})
        if php_source == "the website's response headers":
            findings.append(_finding(
                "disclosure:php", "low", "Your website tells everyone which PHP version it runs",
                f"Every visitor (and attack robot) can see 'PHP/{php_version}'. This makes it easy to target "
                "you the moment a new flaw is announced.",
                "Turn off 'expose_php' in your PHP settings, or ask your host to hide the X-Powered-By header.",
                category="php", guide="php_upgrade",
                support_ask="Please set expose_php = Off so my website stops advertising its PHP version."))
    else:
        uses_php = (wp_detected or ".php" in html or "phpsessid" in home.header("set-cookie").lower()
                    or "php" in xpb.lower())
        if uses_php:
            recent_crit = [a for a in rules.get("advisories", []) if a.get("product") == "php"
                           and a.get("severity") == "critical" and _recent(a.get("published"), 45, today)]
            sev = "medium" if recent_crit else "info"
            extra = ""
            if recent_crit:
                extra = (f" This matters right now because of '{recent_crit[0].get('name') or recent_crit[0]['id']}', "
                         "a critical PHP flaw being actively attacked.")
            findings.append(_finding(
                "php:unknown", sev, "We can't see your PHP version from the outside - please confirm it",
                "Hiding the version is good practice, but it means we can't tell whether you're protected." + extra,
                "Use the 'Get exact PHP version' helper on this page (upload one small file), or send your hosting "
                "company the ready-made message below.",
                category="php", guide="check_file",
                support_ask=("Which exact PHP version is my website running, and does it include the latest "
                             "security fixes?" + (" (" + ", ".join(recent_crit[0].get("cves", [])) + ")"
                                                  if recent_crit and recent_crit[0].get("cves") else ""))))

    # 7. WordPress core + plugins
    wp_version = _wp_version_from_html(html)
    if wp_detected and not wp_version:
        try:
            feed = netsafe.fetch(base + "/feed/", allow_private=allow_private, verify_tls=verify, timeout=8,
                                 max_body=64 * 1024)
            mm = re.search(r"wordpress\.org/\?v=([\d.]+)", feed.text())
            if mm:
                wp_version = mm.group(1)
        except Exception:
            pass
    facts["wordpress"] = bool(wp_detected or wp_version)
    facts["wordpress_version"] = wp_version
    wp_latest = None
    if wp_version:
        inventory.append({"product": "wordpress", "version": wp_version, "source": "your site's public pages"})
        if check_wp_latest:
            wp_latest = wordpress_latest()
            facts["wordpress_latest"] = wp_latest
        findings.append(_finding(
            "disclosure:wp", "low", "Your site shows its WordPress version publicly",
            "Attack robots read this to pick targets.",
            "Many security plugins have a 'hide WordPress version' option.",
            category="wordpress", guide="wordpress"))
    if facts["wordpress"]:
        inventory.extend(_detect_plugins(html, base, allow_private, verify, wp_version))

    # 7b. Web server and other site builders
    srv = facts.get("server") or ""
    ms = re.match(r"(?i)\s*(apache|nginx)/(\d+\.\d+(?:\.\d+)?)", srv)
    if ms:
        inventory.append({"product": ms.group(1).lower(), "version": ms.group(2), "source": "the Server header",
                          "distro": bool(re.search(r"(?i)ubuntu|debian|centos|red hat|fedora|rocky|alma", srv))})
    inventory.extend(_detect_other_cms(home, html, base, allow_private, verify))

    # 7c. Is the site sending visitors to a different website?
    final_host = urlsplit(home.url).hostname or ""
    if final_host and _site_domain(final_host) != _site_domain(urlsplit(base).hostname or ""):
        findings.append(_finding(
            "redirect:offsite", "medium", "Your website sends visitors to a different website",
            f"When we opened your address, we ended up at {final_host}. If you moved your site there on purpose, "
            "mark this as handled. If you didn't, someone may have changed your site without permission.",
            "Check with whoever manages your website. If nobody set this up, contact your hosting company today.",
            category="integrity", guide="down",
            support_ask=f"My website is redirecting visitors to {final_host} and I didn't set that up. Can you check?"))

    # 7d. Outside code loaded by the homepage (compared between checks by the engine)
    facts["script_hosts"] = _script_hosts(html, urlsplit(base).hostname or "")

    # 7e. Match everything against curated advisories + live threat intel
    soft = assess(inventory, rules, intel, facts=facts, today=today, wp_latest=wp_latest)
    for f in soft:
        if f["key"].startswith("adv:") and facts.get("php_sapi") == "apache2handler":
            f["detail"] += ("\n\nYour server runs PHP as 'mod_php' (inside Apache), which is the setup "
                            "attackers can hit most easily. Treat this as an emergency.")
        if f["key"] == "adv:PHP2SHELL-2026" and facts.get("upload_progress"):
            f["fix"] += (" Temporary stopgap while you wait: turn off 'session.upload_progress' in your "
                         "PHP settings (this blocks one known attack path - it is NOT a full fix).")
    findings.extend(soft)
    facts["software"] = [{k: i.get(k) for k in ("product", "version", "source", "name", "distro")}
                         for i in inventory]

    # 8. Browser safety headers (one combined, low-severity finding)
    if facts.get("https"):
        missing = []
        if "strict-transport-security" not in home.headers:
            missing.append("Strict-Transport-Security (forces the secure connection)")
        if home.header("x-content-type-options").lower() != "nosniff":
            missing.append("X-Content-Type-Options (stops file-type tricks)")
        csp = home.header("content-security-policy").lower()
        if "x-frame-options" not in home.headers and "frame-ancestors" not in csp:
            missing.append("X-Frame-Options (stops your site being hidden inside other sites)")
        if missing:
            findings.append(_finding(
                "headers:missing", "low", "A few browser safety settings are missing",
                "These optional settings tell browsers to add extra protection for your visitors. Missing: "
                + "; ".join(missing) + ".",
                "A security plugin (for WordPress) or your host can turn these on. Low priority - fix the "
                "red and orange items first.", category="hardening", guide="headers",
                support_ask="Please add the HSTS, X-Content-Type-Options and X-Frame-Options security headers to my website."))

    if re.search(r"/\d+\.\d+", srv):
        findings.append(_finding(
            "disclosure:server", "low", "Your web server announces its exact version",
            f"Visitors can see '{srv}'. It helps attackers pick known flaws.",
            "Ask your host to hide the server version (ServerTokens Prod for Apache, server_tokens off for nginx).",
            category="hardening", guide="headers",
            support_ask="Please hide the web server version from the Server header."))

    worst = min((SEV_RANK.get(f["severity"], 9) for f in findings), default=9)
    status = "critical" if worst == 0 else "warning" if worst <= 2 else "ok"
    return _result(status, findings, facts, started)


def _site_domain(host: str) -> str:
    """Rough 'registrable domain': www.shop.example.co.uk -> example.co.uk"""
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and len(labels[-2]) <= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _script_hosts(html: str, own_host: str) -> list[str]:
    own = _site_domain(own_host)
    hosts = set()
    for m in re.finditer(r"<script[^>]+src=[\"']((?:https?:)?//[^\"'/]+)", html, re.I):
        h = urlsplit(m.group(1) if m.group(1).startswith("http") else "https:" + m.group(1)).hostname
        if h and _site_domain(h) != own:
            hosts.add(h.lower())
    return sorted(hosts)[:40]


def _detect_plugins(html: str, base: str, allow_private: bool, verify: bool, wp_version: str | None):
    slugs: list[str] = []
    for m in re.finditer(r"/wp-content/plugins/([a-z0-9][a-z0-9_-]{1,80})/", html):
        s = m.group(1).lower()
        if s not in slugs:
            slugs.append(s)
        if len(slugs) >= 20:
            break
    hints = {}
    for m in re.finditer(r"/wp-content/plugins/([a-z0-9][a-z0-9_-]{1,80})/[^\"'?\s]+\?ver=([\d.]+)", html):
        hints.setdefault(m.group(1).lower(), m.group(2))

    def readme(slug):
        try:
            r = netsafe.fetch(f"{base}/wp-content/plugins/{slug}/readme.txt", allow_private=allow_private,
                              verify_tls=verify, follow_redirects=False, timeout=8, max_body=16 * 1024)
            if r.status == 200 and b"<html" not in r.body[:600].lower():
                t = r.text()
                mv = re.search(r"(?im)^\s*Stable tag:\s*([\d.]+)", t)
                mn = re.search(r"^\s*===\s*(.+?)\s*===", t)
                return slug, (mv.group(1) if mv else None), (mn.group(1)[:120] if mn else None)
        except Exception:
            pass
        return slug, None, None

    items = []
    with cf.ThreadPoolExecutor(max_workers=6) as ex:
        for slug, ver, name in ex.map(readme, slugs):
            source = "the plugin's readme file"
            if not ver and hints.get(slug) and hints[slug] != wp_version:
                ver, source = hints[slug], "the plugin's file links (may be approximate)"
            items.append({"product": "wp-plugin:" + slug, "version": ver, "name": name or slug,
                          "source": source if ver else "detected (version hidden)"})
    return items


def _detect_other_cms(home, html: str, base: str, allow_private: bool, verify: bool):
    items = []
    gen = home.header("x-generator") + " " + " ".join(
        re.findall(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html, re.I))
    md = re.search(r"Drupal (\d+)", gen)
    if md:
        ver = md.group(1)
        for path in ("/core/CHANGELOG.txt", "/CHANGELOG.txt"):
            try:
                r = netsafe.fetch(base + path, allow_private=allow_private, verify_tls=verify,
                                  follow_redirects=False, timeout=8, max_body=4096)
                mm = re.search(r"Drupal (\d+\.\d+(?:\.\d+)?)", r.text()) if r.status == 200 else None
                if mm:
                    ver = mm.group(1)
                    break
            except Exception:
                pass
        items.append({"product": "drupal", "version": ver, "source": "your site's public pages"})
    if "joomla" in gen.lower():
        ver = None
        try:
            r = netsafe.fetch(base + "/administrator/manifests/files/joomla.xml", allow_private=allow_private,
                              verify_tls=verify, follow_redirects=False, timeout=8, max_body=8192)
            mm = re.search(r"<version>([\d.]+)</version>", r.text()) if r.status == 200 else None
            ver = mm.group(1) if mm else None
        except Exception:
            pass
        items.append({"product": "joomla", "version": ver, "source": "your site's public files" if ver else
                      "detected (version hidden)"})
    return items


def _recent(date_str, days, today=None) -> bool:
    try:
        d = _dt.date.fromisoformat(date_str)
    except Exception:
        return False
    return 0 <= ((today or _dt.date.today()) - d).days <= days


def _result(status, findings, facts, started):
    findings = sort_findings(findings)
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {"status": status, "findings": findings, "facts": facts, "counts": counts,
            "duration_ms": int((time.time() - started) * 1000)}


def recompute_status(findings: list[dict], down: bool = False) -> str:
    if down:
        return "down"
    worst = min((SEV_RANK.get(f["severity"], 9) for f in findings), default=9)
    return "critical" if worst == 0 else "warning" if worst <= 2 else "ok"
