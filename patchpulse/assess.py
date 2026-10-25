"""Turn a website's software inventory + threat intel into plain-English findings."""

from __future__ import annotations

import datetime as _dt
import hashlib

from . import intel as intel_mod
from .intel import PLUGIN_PREFIX, PRODUCTS, cycle_for, vcmp, vt, vulns_for
from .rules import evaluate_php

TIERS = [("critical", "exploited"), ("high", "critical-rated"), ("medium", "serious"), ("low", "lower-risk")]
DISTROS = ("ubuntu", "debian", "centos", "red hat", "rhel", "fedora", "almalinux", "rocky", "suse", "deb", "el7",
           "el8", "el9")


def display_name(item: dict, intel: dict) -> str:
    p = item["product"]
    if p.startswith(PLUGIN_PREFIX):
        slug = p[len(PLUGIN_PREFIX):]
        name = (intel.get("plugins", {}).get(slug) or {}).get("name") or item.get("name") or slug
        return f"the “{name}” WordPress plugin"
    return PRODUCTS.get(p, {}).get("display", p)


def _cap(s: str) -> str:
    return s[:1].upper() + s[1:]


def _guide(product: str) -> str:
    if product == "php":
        return "php_upgrade"
    if product == "wordpress":
        return "wordpress"
    if product.startswith(PLUGIN_PREFIX):
        return "wp_plugin"
    if product in ("apache", "nginx"):
        return "server"
    return "cms"


def _fix_text(product, disp, target, version):
    to = f" to {target} or newer" if target else " to the newest version"
    if product == "php":
        return (f"Update PHP{to}. On regular web hosting your hosting company controls this - send them the "
                "ready-made message below. If you run your own server, update the PHP packages and restart PHP.")
    if product == "wordpress":
        return f"Make a backup, then go to your WordPress Dashboard > Updates and update WordPress{to}."
    if product.startswith(PLUGIN_PREFIX):
        return (f"In your WordPress Dashboard open Plugins and click 'Update now' under {disp}. If no update is "
                "offered, deactivate and delete the plugin until a fixed version is released.")
    if product in ("apache", "nginx"):
        return (f"Your hosting company (or whoever manages your server) needs to update the {disp}{to}. "
                "Send them the ready-made message below.")
    return f"Update {disp}{to}. Your web developer or hosting company can do this; send them the message below."


def _target(matches, version):
    """Smallest fixed version in the same branch that clears every matched flaw."""
    v = vt(version)
    fixes = []
    for m in matches:
        for r in m.get("ranges", []):
            if intel_mod.in_range(version, r) and r.get("ee"):
                fixes.append(r["ee"])
    same = [f for f in fixes if vt(f)[:2] == v[:2]] or fixes
    return max(same, key=vt) if same else None


def _os_hint(facts: dict) -> str | None:
    s = (facts.get("server") or "").lower() + " " + (facts.get("php_sapi") or "")
    if "win32" in s or "win64" in s or "microsoft-iis" in s:
        return "windows"
    if any(k in s for k in ("ubuntu", "debian", "centos", "red hat", "unix", "linux", "fedora")):
        return "linux"
    return None


def vuln_findings(item: dict, intel: dict, covered: set, facts: dict) -> list[dict]:
    product, version = item["product"], item.get("version")
    if not version or len(vt(version)) < 2:
        return []
    disp = display_name(item, intel)
    os_hint = _os_hint(facts)
    cycles = ((intel.get("products") or {}).get(product) or {}).get("cycles") or {}
    c = cycle_for(version, cycles) if cycles else None
    branch_latest = (cycles.get(c) or {}).get("latest") if c else None
    on_branch_latest = bool(branch_latest) and vcmp(vt(version), vt(branch_latest)) >= 0
    matches = []
    for v in vulns_for(product, version, intel):
        if v["id"] in covered:
            continue
        if v.get("src") == "cna" and on_branch_latest:
            continue  # vendor ranges are coarse; the newest patch of a branch includes backported fixes
        sev = intel_mod.severity_of(v)
        plat = (v.get("platform") or "").lower()
        note = ""
        if plat:
            if os_hint and plat not in os_hint and os_hint not in plat:
                continue  # e.g. a Windows-only PHP flaw on a Linux server
            if not os_hint:
                sev = {"critical": "high", "high": "medium"}.get(sev, sev)
                note = f" (only affects {disp} running on {plat.title()})"
        matches.append((sev, v, note))
    if not matches:
        return []
    distro = item.get("distro")
    out = []
    for sev, label in TIERS:
        group = [(v, n) for s, v, n in matches if s == sev]
        if not group:
            continue
        group.sort(key=lambda g: (-(g[0].get("score") or 0), g[0]["id"]), reverse=False)
        ids = sorted(v["id"] for v, _ in group)
        n = len(group)
        lines = []
        for v, note in group[:12]:
            fix = next((r.get("ee") for r in v["ranges"] if intel_mod.in_range(version, r) and r.get("ee")), None)
            what = v.get("name") or (f"security flaw rated {v['score']:.1f} out of 10" if v.get("score") else "security flaw")
            lines.append(f"• {v['id']}: {what}{note}" + (f" - fixed in {fix}" if fix else ""))
        if n > 12:
            lines.append(f"• and {n - 12} more")
        if sev == "critical":
            title = (f"Attackers are actively using a flaw in {disp} {version}" if n == 1 else
                     f"Attackers are actively using {n} flaws in {disp} {version}")
            lead = (f"{'This flaw is' if n == 1 else 'These flaws are'} on the U.S. Cybersecurity and Infrastructure "
                    "Security Agency's list of flaws being used in real attacks (CISA Known Exploited "
                    f"Vulnerabilities), or {'has' if n == 1 else 'have'} been reported as actively exploited.")
            if any(v.get("ransomware") for v, _ in group):
                lead += " At least one is known to be used by ransomware gangs."
        else:
            title = (f"{_cap(disp)} {version} has {n} known {label} security flaw{'s' if n > 1 else ''}")
            lead = {"high": "These are rated critical (9 or higher out of 10). Attackers often start using flaws "
                            "like these within days of them being published.",
                    "medium": "These are rated serious (7 to 8.9 out of 10).",
                    "low": "These are lower-risk, but still worth fixing when you next update."}[sev]
        detail = lead + "\n\n" + "\n".join(lines)
        final_sev = sev
        if distro and product in ("php", "apache", "nginx"):
            detail += ("\n\nYour server uses a Linux distribution's build of this software. Distributions often "
                       "include security fixes without changing the version number, so ask your host to confirm. "
                       "If they say it's patched, mark this as handled.")
            final_sev = {"critical": "high"}.get(sev, sev)
        target = _target([v for v, _ in group], version)
        if branch_latest and (target is None or all(v.get("src") == "cna" for v, _ in group)):
            target = branch_latest  # newest patch of the site's own branch carries the backported fixes
        support = (f"My website runs {PRODUCTS.get(product, {}).get('display', disp)} {version}, which has known "
                   f"security flaws ({', '.join(ids[:5])}{', ...' if n > 5 else ''}). Please update it"
                   + (f" to {target} or newer" if target else "") + ", or confirm the fixes are already applied.")
        refs = [intel_mod.NVD_DETAIL.format(cve=i) for i in ids[:6]]
        if sev == "critical":
            refs.insert(0, intel_mod.KEV_PAGE)
        h = hashlib.sha256(",".join(ids).encode()).hexdigest()[:10]
        out.append({
            "key": f"vuln:{product}:{sev}:{h}", "severity": final_sev, "category": "software",
            "title": title, "detail": detail + "\n\nSources: CISA Known Exploited Vulnerabilities catalog and the "
                                               "NIST National Vulnerability Database.",
            "fix": _fix_text(product, disp, target, version), "support_ask": support,
            "references": refs, "cves": ids, "guide": _guide(product), "can_dismiss": bool(distro),
        })
    return out


def lifecycle_findings(item: dict, intel: dict, today: _dt.date, wp_latest: str | None) -> list[dict]:
    product, version = item["product"], item.get("version")
    if not version:
        return []
    disp = display_name(item, intel)
    out = []
    if product.startswith(PLUGIN_PREFIX):
        slug = product[len(PLUGIN_PREFIX):]
        info = intel.get("plugins", {}).get(slug) or {}
        latest = info.get("latest") or item.get("latest")
        if info.get("closed"):
            out.append({
                "key": f"plugin:closed:{slug}", "severity": "high", "category": "software",
                "title": f"{_cap(disp)} was removed from WordPress.org",
                "detail": "WordPress.org closes plugins that are abandoned or have unfixed security problems. "
                          "It will not get any more updates.",
                "fix": "Replace it with a maintained alternative, then deactivate and delete it.",
                "support_ask": f"Please help me replace the {slug} plugin, which was removed from WordPress.org.",
                "references": [f"https://wordpress.org/plugins/{slug}/"], "guide": "wp_plugin"})
        elif latest and vt(version) and vcmp(vt(version), vt(latest)) < 0:
            out.append({
                "key": f"plugin:outdated:{slug}", "severity": "medium", "category": "software",
                "title": f"{_cap(disp)} is out of date",
                "detail": f"Your site has version {version}; the current version is {latest}. Out-of-date plugins "
                          "are the most common way WordPress sites get hacked.",
                "fix": "In your WordPress Dashboard open Plugins and click 'Update now' under this plugin.",
                "support_ask": f"Please update the {slug} plugin on my website to version {latest}.",
                "references": [f"https://wordpress.org/plugins/{slug}/"], "guide": "wp_plugin"})
        return out

    cycles = ((intel.get("products") or {}).get(product) or {}).get("cycles") or {}
    if product == "wordpress":
        c = cycle_for(version, cycles) if cycles else None
        branch_latest = cycles.get(c, {}).get("latest") if c else None
        overall = max([x.get("latest") for x in cycles.values() if x.get("latest")] + ([wp_latest] if wp_latest else []),
                      key=vt, default=None)
        if branch_latest and vcmp(vt(version), vt(branch_latest)) < 0:
            out.append({
                "key": "wp:outdated", "severity": "high", "category": "wordpress",
                "title": "WordPress is missing a security update",
                "detail": f"Your site runs WordPress {version}. The latest security release for your version is "
                          f"{branch_latest}" + (f" (newest WordPress overall: {overall})." if overall else ".") +
                          " Outdated WordPress is the #1 way small sites get hacked.",
                "fix": f"Make a backup, then go to Dashboard > Updates and update to {branch_latest} or newer.",
                "support_ask": f"Please update WordPress on my website to {branch_latest} or newer (currently {version}).",
                "references": ["https://wordpress.org/download/releases/"], "guide": "wordpress"})
        elif overall and vcmp(vt(version), vt(overall)) < 0:
            sev = "medium" if (not c or vt(overall)[0] > vt(version)[0]) else "low"
            out.append({
                "key": "wp:behind", "severity": sev, "category": "wordpress",
                "title": "A newer version of WordPress is available",
                "detail": f"Your site runs WordPress {version}, which has its security fixes, but the newest version "
                          f"is {overall}. Older versions eventually stop getting fixes.",
                "fix": "When convenient, make a backup and update from Dashboard > Updates.",
                "support_ask": f"Please update WordPress on my website to {overall}.",
                "references": ["https://wordpress.org/download/releases/"], "guide": "wordpress"})
        return out

    if not cycles:
        return out
    c = cycle_for(version, cycles)
    if not c:
        return out
    info = cycles[c]
    rec = max((k for k, v in cycles.items() if not v.get("eol") or v["eol"] > today.isoformat()), key=vt, default=None)
    eol = info.get("eol")
    host_side = product in ("php", "apache", "nginx")
    if eol and eol <= today.isoformat():
        out.append({
            "key": f"{product}:eol", "severity": "high", "category": "software",
            "title": f"{_cap(disp)} {c} is retired and no longer gets security fixes",
            "detail": f"{_cap(disp)} {c} stopped receiving security updates" +
                      (f" on {_dt.date.fromisoformat(eol):%B %d, %Y}." if eol != "1970-01-01" else ".") +
                      " Any new flaw found in it will never be fixed.",
            "fix": f"Move to {disp} {rec} or newer." + (" Most hosting control panels have a version setting for "
                                                         "this, or your host can do it." if host_side else ""),
            "support_ask": f"Please move my website from {PRODUCTS[product]['display']} {c} (no longer supported) "
                           f"to {rec} or newer.",
            "references": [f"https://endoflife.date/{PRODUCTS[product]['eol']}"], "guide": _guide(product)})
    elif eol:
        days = (_dt.date.fromisoformat(eol) - today).days
        if days <= 90:
            out.append({
                "key": f"{product}:eol-soon", "severity": "medium", "category": "software",
                "title": f"{_cap(disp)} {c} retires in {days} days",
                "detail": f"{_cap(disp)} {c} stops getting security updates on "
                          f"{_dt.date.fromisoformat(eol):%B %d, %Y}. Plan the switch now so you're not rushing "
                          "during the next emergency.",
                "fix": f"Schedule a move to {disp} {rec} or newer.",
                "support_ask": f"Before {_dt.date.fromisoformat(eol):%B %d, %Y}, please move my website to "
                               f"{PRODUCTS[product]['display']} {rec} or newer.",
                "references": [f"https://endoflife.date/{PRODUCTS[product]['eol']}"], "guide": _guide(product)})
    latest = info.get("latest")
    if latest and len(vt(version)) >= 3 and vcmp(vt(version), vt(latest)) < 0 and not (eol and eol <= today.isoformat()):
        distro = item.get("distro")
        out.append({
            "key": f"{product}:behind", "severity": "low" if distro else "medium", "category": "software",
            "title": f"{_cap(disp)} is missing the latest patch release",
            "detail": f"Your site runs {disp} {version}; the newest release for {c} is {latest}. Patch releases "
                      "usually contain security fixes, so staying current closes holes before attackers find them."
                      + (" Your server uses a Linux distribution's build, which may already include the fixes - "
                         "ask your host to confirm." if distro else ""),
            "fix": f"Update {disp} to {latest}." + (" Your hosting company controls this on regular hosting."
                                                    if host_side else ""),
            "support_ask": f"Please update {PRODUCTS[product]['display']} on my website from {version} to {latest}.",
            "references": [f"https://endoflife.date/{PRODUCTS[product]['eol']}"], "guide": _guide(product),
            "can_dismiss": bool(distro)})
    return out


_SNAP = None


def _snapshot() -> dict:
    global _SNAP
    if _SNAP is None:
        _SNAP = intel_mod.load_snapshot()
    return _SNAP


def assess(inventory: list[dict], rules: dict, intel: dict | None, *, facts: dict | None = None,
           today: _dt.date | None = None, wp_latest: str | None = None) -> list[dict]:
    today = today or _dt.date.today()
    intel = dict(intel or intel_mod.empty_intel())
    facts = facts or {}
    # Fall back to the built-in end-of-life snapshot for anything live data hasn't covered yet
    prods = dict(intel.get("products") or {})
    for k, cycles in _snapshot().items():
        if not (prods.get(k) or {}).get("cycles"):
            prods[k] = {"cycles": cycles, "source": "built-in snapshot"}
    intel["products"] = prods
    findings: list[dict] = []
    covered = {c for a in rules.get("advisories", []) for c in a.get("cves", [])}
    for item in inventory:
        product, version = item["product"], item.get("version")
        if product == "php" and version:
            has_cycles = bool(((intel.get("products") or {}).get("php") or {}).get("cycles"))
            php = evaluate_php(version, rules, today=today, source=item.get("source", ""),
                               include_eol=not has_cycles)
            findings.extend(php)
        findings.extend(lifecycle_findings(item, intel, today, wp_latest))
        findings.extend(vuln_findings(item, intel, covered, facts))
    # one EOL message per product is enough
    seen, out = set(), []
    for f in findings:
        if f["key"] in seen:
            continue
        seen.add(f["key"])
        out.append(f)
    return out
