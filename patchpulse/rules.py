"""Threat rules: a small, data-driven engine.

Rules live in JSON (bundled default + optional updates fetched over HTTPS
from a URL the seller controls). New threats are shipped as data, never
code, so a bad rules file can at worst mis-label a finding - it can never
run anything on a customer's machine.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import ssl
import urllib.request
from pathlib import Path

from . import USER_AGENT

BUNDLED = Path(__file__).parent / "data" / "rules.json"
SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
_VER_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")
_MAX_RULES_BYTES = 2 * 1024 * 1024


class RulesError(Exception):
    pass


def parse_version(s: str | None):
    """'8.1.2-1ubuntu2.14' -> ((8, 1, 2), '-1ubuntu2.14'). None if unparseable."""
    if not s:
        return None
    m = _VER_RE.search(str(s))
    if not m:
        return None
    nums = (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))
    return nums, str(s)[m.end():]


def branch_of(ver: tuple) -> str:
    return f"{ver[0]}.{ver[1]}"


def _vt(s: str) -> tuple:
    p = parse_version(s)
    if not p:
        raise RulesError(f"bad version '{s}'")
    return p[0]


def validate(rules: dict) -> dict:
    """Strict schema check. Returns the rules or raises RulesError."""
    if not isinstance(rules, dict) or rules.get("schema") != 1:
        raise RulesError("unsupported rules schema")
    if not isinstance(rules.get("rules_version"), str):
        raise RulesError("missing rules_version")
    prods = rules.get("products", {})
    if not isinstance(prods, dict):
        raise RulesError("products must be an object")
    for name, p in prods.items():
        for br, info in (p.get("branches") or {}).items():
            _dt.date.fromisoformat(info["eol"])
            _vt(br)
    advs = rules.get("advisories", [])
    if not isinstance(advs, list):
        raise RulesError("advisories must be a list")
    for a in advs:
        for k in ("id", "product", "severity", "title", "summary", "fix"):
            if not isinstance(a.get(k), str) or not a[k]:
                raise RulesError(f"advisory missing '{k}'")
        if a["severity"] not in SEV_RANK:
            raise RulesError(f"bad severity in {a['id']}")
        for br, v in (a.get("fixed_in") or {}).items():
            _vt(br), _vt(v)
        if a.get("affected_from"):
            _vt(a["affected_from"])
        for ref in a.get("references", []):
            if not str(ref).startswith("https://"):
                raise RulesError("references must be https links")
    return rules


def load_bundled() -> dict:
    return validate(json.loads(BUNDLED.read_text("utf-8")))


def newer(a: dict, b: dict) -> bool:
    """True if rules a is newer than rules b (compare version strings numerically)."""
    def key(r):
        return tuple(int(x) if x.isdigit() else 0 for x in r["rules_version"].split("."))
    return key(a) > key(b)


def fetch_remote(url: str, timeout: float = 15.0) -> dict:
    if not url.startswith("https://"):
        raise RulesError("Rules update address must start with https://")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    ctx = ssl.create_default_context()
    try:
        import certifi  # type: ignore
        ctx.load_verify_locations(certifi.where())
    except Exception:
        pass
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        data = r.read(_MAX_RULES_BYTES + 1)
    if len(data) > _MAX_RULES_BYTES:
        raise RulesError("rules file too large")
    import os
    from .licensing import LicenseError, unwrap_rules
    try:
        envelope = json.loads(data.decode("utf-8"))
        inner = unwrap_rules(envelope, require_signature=os.environ.get("PATCHPULSE_UNSIGNED_RULES") != "1")
        return validate(inner)
    except LicenseError as e:
        raise RulesError(str(e))
    except (ValueError, KeyError, TypeError) as e:
        raise RulesError(f"rules file is not valid: {e}")


def evaluate_php(version_str: str, rules: dict, today: _dt.date | None = None,
                 source: str = "", include_eol: bool = True) -> list[dict]:
    """Return findings for an observed PHP version."""
    today = today or _dt.date.today()
    parsed = parse_version(version_str)
    if not parsed:
        return []
    ver, suffix = parsed
    br = branch_of(ver)
    findings: list[dict] = []
    distro_build = bool(re.search(r"(ubuntu|deb|el\d|fc\d|\+)", suffix or "", re.I))
    seen_from = f" (seen via {source})" if source else ""

    for a in rules.get("advisories", []):
        if a.get("product") != "php":
            continue
        if a.get("affected_from") and ver < _vt(a["affected_from"]):
            continue
        fixed = a.get("fixed_in") or {}
        vulnerable = False
        no_fix = False
        if br in fixed:
            vulnerable = ver < _vt(fixed[br])
        else:
            newest_fixed_branch = max((_vt(b) for b in fixed), default=None)
            if newest_fixed_branch and ver[:2] > newest_fixed_branch[:2]:
                vulnerable = False  # newer branch than any listed: released after fix
            elif a.get("unlisted_branches") == "vulnerable":
                vulnerable, no_fix = True, True
        if not vulnerable:
            continue
        detail = a["summary"] + f"\n\nYour website reports PHP {version_str}{seen_from}."
        if no_fix:
            detail += f" PHP {br} is so old it gets no fix at all - it must be upgraded to a newer version."
        if distro_build and a.get("backport_note"):
            detail += "\n\n" + a["backport_note"]
        findings.append({
            "key": f"adv:{a['id']}",
            "severity": a["severity"],
            "category": "php",
            "title": a["title"],
            "detail": detail,
            "fix": a["fix"],
            "support_ask": a.get("support_ask", ""),
            "references": a.get("references", []),
            "cves": a.get("cves", []),
            "guide": "php_upgrade",
            "can_dismiss": distro_build,
        })

    if not include_eol:
        return findings
    prod = (rules.get("products") or {}).get("php") or {}
    binfo = (prod.get("branches") or {}).get(br)
    rec = prod.get("recommended_branch", "8.4")
    if binfo:
        eol = _dt.date.fromisoformat(binfo["eol"])
        days = (eol - today).days
        if days < 0:
            findings.append({
                "key": "php:eol", "severity": "high", "category": "php",
                "title": f"PHP {br} is retired and no longer gets security fixes",
                "detail": f"PHP {br} stopped receiving security updates on {eol:%B %d, %Y}. "
                          "Any new flaw found in it will never be fixed, so your site stays exposed.",
                "fix": f"Switch your site to PHP {rec} or newer. Most hosting control panels have a "
                       "'PHP version' setting. Test your site afterward; older plugins may need updating first.",
                "support_ask": f"Please move my website from PHP {br} (no longer supported) to PHP {rec} or newer.",
                "references": ["https://www.php.net/supported-versions.php"],
                "guide": "php_upgrade",
            })
        elif days <= int(prod.get("eol_warning_days", 90)):
            findings.append({
                "key": "php:eol-soon", "severity": "medium", "category": "php",
                "title": f"PHP {br} retires in {days} days",
                "detail": f"PHP {br} stops getting security updates on {eol:%B %d, %Y}. Plan the switch now "
                          "so you're not rushing during the next emergency.",
                "fix": f"Schedule a move to PHP {rec} or newer before {eol:%B %d, %Y}.",
                "support_ask": f"Before {eol:%B %d, %Y}, please help me move my website to PHP {rec} or newer.",
                "references": ["https://www.php.net/supported-versions.php"],
                "guide": "php_upgrade",
            })
    elif ver[:2] < (5, 6):
        findings.append({
            "key": "php:eol", "severity": "high", "category": "php",
            "title": f"PHP {br} is extremely old",
            "detail": f"PHP {br} has been retired for many years and has many known break-in flaws.",
            "fix": f"Upgrade to PHP {rec} or newer as soon as possible.",
            "support_ask": f"Please move my website to PHP {rec} or newer.",
            "references": ["https://www.php.net/supported-versions.php"],
            "guide": "php_upgrade",
        })
    return findings


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: (SEV_RANK.get(f.get("severity"), 9), f.get("title", "")))
