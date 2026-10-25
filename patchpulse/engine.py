"""The brain: license gate, continuous threat hunting, scanning, change detection, alerting."""

from __future__ import annotations

import concurrent.futures as cf
import datetime as _dt
import json
import logging
import os
import secrets
import threading
import time

from . import alerts as alerts_mod
from . import config, intel as intel_mod, licensing
from . import rules as rules_mod
from .rules import SEV_RANK
from .scanner import recompute_status, scan_site
from .store import Store

log = logging.getLogger("patchpulse")

DEFAULT_RULES_URL = config.RULES_URL
RULES_CHECK_EVERY = 3 * 3600
LICENSE_CHECK_EVERY = 24 * 3600

# Widely used services that sites legitimately load code from. New code from anywhere
# else is reported once so the owner can confirm they (or their developer) added it.
COMMON_SCRIPT_DOMAINS = {
    "googletagmanager.com", "google-analytics.com", "googleapis.com", "gstatic.com", "google.com",
    "doubleclick.net", "googlesyndication.com", "googleadservices.com", "youtube.com", "ytimg.com",
    "facebook.net", "facebook.com", "fbcdn.net", "twitter.com", "twimg.com", "x.com", "linkedin.com", "licdn.com",
    "pinterest.com", "pinimg.com", "tiktok.com", "instagram.com", "cloudflare.com", "cloudflareinsights.com",
    "jsdelivr.net", "cdnjs.com", "unpkg.com", "jquery.com", "bootstrapcdn.com", "fontawesome.com",
    "stripe.com", "stripe.network", "paypal.com", "paypalobjects.com", "squareup.com", "square.site",
    "shopify.com", "shopifycdn.com", "wp.com", "wordpress.com", "gravatar.com", "jetpack.com",
    "hotjar.com", "clarity.ms", "hs-scripts.com", "hubspot.com", "hsforms.net", "intercom.io", "crisp.chat",
    "tawk.to", "zendesk.com", "zdassets.com", "mailchimp.com", "list-manage.com", "klaviyo.com",
    "trustpilot.com", "vimeo.com", "vimeocdn.com", "wistia.com", "calendly.com", "typekit.net", "adobe.com",
    "recaptcha.net", "hcaptcha.com", "cookielaw.org", "onetrust.com", "cookiebot.com", "usercentrics.eu",
    "elfsight.com", "wix.com", "parastorage.com", "squarespace.com", "sqspcdn.com", "weebly.com",
    "amazon-adsystem.com", "bing.com", "microsoft.com", "clarity.ms", "yandex.ru", "tiqcdn.com",
}


HUB_MAX_AGE = 6 * 3600


def _hub_fresh(generated, now=None) -> bool:
    """True when the hub feed was generated within HUB_MAX_AGE (timestamps are ISO, UTC if no zone)."""
    if not generated:
        return False
    try:
        t = _dt.datetime.fromisoformat(str(generated).replace("Z", "+00:00"))
    except ValueError:
        return False
    if t.tzinfo is None:
        t = t.replace(tzinfo=_dt.timezone.utc)
    age = (now or _dt.datetime.now(_dt.timezone.utc)) - t
    return -_dt.timedelta(minutes=10) <= age <= _dt.timedelta(seconds=HUB_MAX_AGE)


def _domain(host: str) -> str:
    from .scanner import _site_domain
    return _site_domain(host)


class Engine:
    def __init__(self, store: Store):
        self.store = store
        self.pool = cf.ThreadPoolExecutor(max_workers=4, thread_name_prefix="scan")
        self._stop = threading.Event()
        self._rules_lock = threading.Lock()
        self._intel_lock = threading.RLock()
        self._hunt_lock = threading.Lock()
        self.hunting = False
        self.hunter_factory = None  # tests / hub mode can inject a Hunter factory
        self._rules = self._load_rules()
        self._intel = self._load_intel()
        if not self.store.get("install_id"):
            self.store.set("install_id", secrets.token_hex(16))
        for s in self.store.sites():  # clear "scanning" flags left by a crash
            if s["scanning"]:
                self.store.update_site(s["id"], scanning=0)

    # ---------- settings helpers ----------
    def setting(self, key, default=None):
        return self.store.get(key, default)

    @property
    def interval_hours(self) -> float:
        return float(self.setting("scan_interval_hours", config.DEFAULT_SCAN_HOURS))

    @property
    def hunt_minutes(self) -> float:
        return max(15.0, float(self.setting("hunt_minutes", config.HUNT_MINUTES)))

    @property
    def allow_private(self) -> bool:
        return bool(self.setting("allow_private", False)) or os.environ.get("PATCHPULSE_ALLOW_PRIVATE") == "1"

    @property
    def activation_url(self) -> str:
        return (self.setting("activation_url") or config.ACTIVATION_URL or "").strip()

    # ---------- license (no free tier) ----------
    def license_status(self, today: _dt.date | None = None) -> dict:
        """state: none | invalid | expired | needs_activation | revoked | active"""
        key = self.setting("license_key")
        if not key:
            return {"state": "none", "message": "Enter your license key to start monitoring.", "license": None}
        try:
            lic = licensing.parse_license(key, today)
        except licensing.LicenseError as e:
            state = "expired" if "expired" in str(e) else "invalid"
            return {"state": state, "message": str(e), "license": None}
        if self.setting("license_revoked"):
            return {"state": "revoked", "message": "This license has been cancelled. Monitoring is paused.",
                    "license": lic}
        if self.activation_url:
            tok = self.setting("activation_token")
            if not tok:
                return {"state": "needs_activation", "message": "This license needs to be activated online.",
                        "license": lic}
            try:
                p = licensing.check_token(tok, lic.get("id", ""), self.setting("install_id"), today)
                lic = {**lic, "activated_until": p["until"]}
            except licensing.LicenseError as e:
                return {"state": "needs_activation", "message": str(e), "license": lic}
        return {"state": "active", "message": "", "license": lic}

    def license(self) -> dict | None:
        st = self.license_status()
        return st["license"] if st["state"] == "active" else None

    def set_license(self, key: str) -> dict:
        """Validate, activate online if configured, and store. Raises LicenseError."""
        lic = licensing.parse_license(key)
        if self.activation_url:
            try:
                tok = licensing.activate_online(self.activation_url, key, self.setting("install_id"))
            except licensing.ActivationRefused as e:
                raise licensing.LicenseError(str(e))
            except OSError as e:
                raise licensing.LicenseError(f"Couldn't reach the license server to activate ({e}). Check your "
                                             "internet connection and try again.")
            licensing.check_token(tok, lic.get("id", ""), self.setting("install_id"))
            self.store.set("activation_token", tok)
        self.store.set("license_key", "".join(key.split()))
        self.store.set("license_revoked", False)
        self.store.set("license_checked_at", time.time())
        self.store.event("system", f"License activated: {lic.get('plan')} plan")
        return lic

    def remove_license(self):
        key = self.setting("license_key")
        if key and self.activation_url:
            try:
                licensing.activate_online(self.activation_url, key, self.setting("install_id"), "deactivate")
            except Exception:
                pass
        for k in ("license_key", "activation_token"):
            self.store.set(k, None)

    def refresh_license(self, force: bool = False) -> dict:
        key, url = self.setting("license_key"), self.activation_url
        self.store.set("license_checked_at", time.time())
        if not key or not url:
            return self.license_status()
        tok = self.setting("activation_token")
        if tok and not force:
            try:
                lic = licensing.parse_license(key)
                p = licensing.check_token(tok, lic.get("id", ""), self.setting("install_id"))
                left = (_dt.date.fromisoformat(p["until"]) - _dt.date.today()).days
                exp = lic.get("expires")
                near_end = bool(exp) and (_dt.date.fromisoformat(exp) - _dt.date.today()).days <= 10
                if left >= licensing.REFRESH_WHEN_DAYS and not near_end:
                    return self.license_status()
            except licensing.LicenseError:
                pass
        try:
            tok = licensing.activate_online(url, key, self.setting("install_id"), "refresh")
            renewed = licensing.LAST_RESPONSE.get("license_key")
            if renewed:  # subscription renewed: swap in the new key automatically
                try:
                    old_id = licensing.parse_license(key, today=_dt.date.min).get("id")  # may have just expired
                    new = licensing.parse_license(renewed)
                    if new.get("id") == old_id:
                        self.store.set("license_key", "".join(renewed.split()))
                        self.store.event("system", f"License renewed until {new.get('expires') or 'no end date'}")
                except licensing.LicenseError:
                    pass
            self.store.set("activation_token", tok)
            self.store.set("license_revoked", False)
        except licensing.ActivationRefused as e:
            if e.revoked:
                self.store.set("license_revoked", True)
                self.store.set("activation_token", None)
                self.store.event("system", f"License cancelled by the license server: {e}")
        except OSError as e:
            self.store.event("license_error", f"Couldn't reach the license server (will retry): {e}")
        return self.license_status()

    def site_limit(self) -> int:
        return licensing.site_limit(self.license())

    def active_sites(self) -> list[dict]:
        """Sites covered by the current license (oldest first). Empty without a license."""
        limit = self.site_limit()
        if limit <= 0:
            return []
        return sorted(self.store.sites(), key=lambda s: s["id"])[:limit]

    def is_active(self, site_id: int) -> bool:
        return any(s["id"] == site_id for s in self.active_sites())

    def can_add_site(self) -> bool:
        return len(self.store.sites()) < self.site_limit()

    # ---------- curated rules ----------
    def _load_rules(self) -> dict:
        bundled = rules_mod.load_bundled()
        cached = self.store.get("rules_cache")
        if cached:
            try:
                cached = rules_mod.validate(cached)
                if rules_mod.newer(cached, bundled):
                    return cached
            except rules_mod.RulesError:
                pass
        return bundled

    @property
    def rules(self) -> dict:
        with self._rules_lock:
            return self._rules

    def update_rules(self, rescan: bool = True) -> dict:
        url = self.setting("rules_url", DEFAULT_RULES_URL) or DEFAULT_RULES_URL
        self.store.set("rules_checked_at", time.time())
        if not url:
            return {"updated": False, "message": "Using the built-in advisories plus live threat hunting.",
                    "rules_version": self.rules["rules_version"]}
        remote = rules_mod.fetch_remote(url)
        if rules_mod.newer(remote, self.rules):
            with self._rules_lock:
                self._rules = remote
            self.store.set("rules_cache", remote)
            self.store.event("rules", f"Advisories updated to {remote['rules_version']}")
            if rescan:
                self.scan_all("new advisory")
            return {"updated": True, "message": f"Advisories updated to {remote['rules_version']}. "
                                                "Re-checking all websites now.",
                    "rules_version": remote["rules_version"]}
        return {"updated": False, "message": "You already have the newest advisories.",
                "rules_version": self.rules["rules_version"]}

    # ---------- threat intel / hunting ----------
    def _load_intel(self) -> dict:
        d = self.store.get("intel")
        if isinstance(d, dict) and d.get("schema") == 1:
            return d
        return intel_mod.empty_intel()

    @property
    def intel(self) -> dict:
        with self._intel_lock:
            return self._intel

    def watched_plugins(self) -> list[str]:
        slugs = set()
        for s in self.active_sites():
            scan = self.store.latest_scan(s["id"])
            for item in ((scan or {}).get("facts") or {}).get("software", []) or []:
                p = item.get("product") or ""
                if p.startswith(intel_mod.PLUGIN_PREFIX):
                    slugs.add(p[len(intel_mod.PLUGIN_PREFIX):])
        return sorted(slugs)

    def _site_products(self, site_id: int) -> set:
        scan = self.store.latest_scan(site_id)
        return {i.get("product") for i in ((scan or {}).get("facts") or {}).get("software", []) or []}

    def hunt(self, *, plugins_only: list[str] | None = None, hunter_factory=None, rescan: bool = True) -> dict:
        """One threat hunt. Single-flight: returns immediately if one is already running."""
        if not self._hunt_lock.acquire(blocking=False):
            return {"started": False, "message": "A threat hunt is already running."}
        self.hunting = True
        try:
            with self._intel_lock:
                work = json.loads(json.dumps(self._intel))
            make = hunter_factory or self.hunter_factory or (
                lambda d: intel_mod.Hunter(d, nvd_api_key=self.setting("nvd_api_key") or ""))
            h = make(work)
            skip_core = False
            hub_url = (self.setting("intel_url") or config.INTEL_URL or "").strip()
            if hub_url and plugins_only is None:
                try:
                    env = intel_mod.http_json(hub_url)
                    hub = intel_mod.validate_intel(licensing.unwrap_feed(env, "intel"))
                    before = set(work.get("vulns", {}))
                    intel_mod.merge_hub(work, hub)
                    h.new_ids |= set(work["vulns"]) - before
                    # only lean on the hub while it's fresh; a stalled hub must never stop hunting
                    skip_core = _hub_fresh(hub.get("generated"))
                    if not skip_core:
                        work.setdefault("sources", {})["hub"] = {"ok": False, "error": "hub feed is stale; hunting directly"}
                except Exception as e:
                    work.setdefault("sources", {})["hub"] = {"ok": False, "error": str(e)[:200]}
            pre_new = set(h.new_ids)
            if plugins_only is not None:
                h.hunt_plugins(plugins_only)
                work["generated"] = h.now().isoformat(timespec="seconds")
                res = {"new": sorted(h.new_ids), "errors": h.errors}
            else:
                res = h.run(self.watched_plugins(), skip_core=skip_core)
                res["new"] = sorted(set(res["new"]) | pre_new)
            with self._intel_lock:
                self._intel = work
                self.store.set("intel", work)
            self.store.set("hunt_at", time.time())
            changed_products = {k.split("|", 1)[1] for k in res["new"]}
            rescanned = 0
            if changed_products and rescan:
                for s in self.active_sites():
                    if self._site_products(s["id"]) & changed_products:
                        rescanned += self.scan_async(s["id"], "new threat")
            if res["new"] and plugins_only is None:
                self.store.event("hunt", f"Threat hunt: {len(res['new'])} new or changed flaws for website "
                                         f"software" + (f"; re-checking {rescanned} website(s) that may be affected"
                                                        if rescanned else ""))
            if res["errors"] and plugins_only is None:
                self.store.event("hunt_error", "Some threat sources couldn't be reached (will retry): "
                                 + "; ".join(res["errors"][:3]))
            return {"started": True, "new": len(res["new"]), "rescanned": rescanned, "errors": res["errors"]}
        finally:
            self.hunting = False
            self._hunt_lock.release()

    def hunt_async(self, **kw) -> bool:
        if self.hunting:
            return False
        threading.Thread(target=self._safe_hunt, kwargs=kw, name="hunt", daemon=True).start()
        return True

    def _safe_hunt(self, **kw):
        try:
            self.hunt(**kw)
        except Exception:
            log.exception("threat hunt failed")

    def intel_summary(self) -> dict:
        i = self.intel
        src = i.get("sources", {})
        return {"last_hunt": self.setting("hunt_at"), "hunting": self.hunting,
                "kev_count": i.get("kev_count", 0), "kev_version": i.get("kev_version"),
                "tracked_flaws": len(i.get("vulns", {})),
                "exploited_flaws": sum(1 for v in i.get("vulns", {}).values() if v.get("exploited")),
                "plugins_watched": len(i.get("plugins", {})),
                "sources": {k: {"ok": v.get("ok"), "at": v.get("at")} for k, v in src.items()},
                "every_minutes": self.hunt_minutes, "notice": intel_mod.NVD_NOTICE}

    # ---------- scanning ----------
    def scan_async(self, site_id: int, reason: str = "manual") -> bool:
        site = self.store.site(site_id)
        if not site or site["scanning"] or not self.is_active(site_id):
            return False
        self.store.update_site(site_id, scanning=1)
        self.pool.submit(self._scan_job, site_id, reason)
        return True

    def scan_all(self, reason: str = "manual") -> int:
        return sum(self.scan_async(s["id"], reason) for s in self.active_sites())

    def scan_now(self, site_id: int, reason: str = "manual") -> dict | None:
        """Synchronous scan (CLI / tests)."""
        self.store.update_site(site_id, scanning=1)
        self._scan_job(site_id, reason)
        return self.view(site_id)

    def _scan_job(self, site_id: int, reason: str):
        site = self.store.site(site_id)
        if not site:
            return
        try:
            rules = self.rules
            kw = dict(allow_private=self.allow_private, check_token=site["check_token"], intel=self.intel)
            try:
                result = scan_site(site["url"], rules, **kw)
                if result["status"] == "down":  # one retry before declaring it down
                    time.sleep(0 if os.environ.get("PATCHPULSE_FAST_RETRY") else 20)
                    result = scan_site(site["url"], rules, **kw)
            except Exception as e:  # UnsafeTarget, bad URL, unexpected
                log.exception("scan failed for %s", site["url"])
                result = {"status": "error", "findings": [], "facts": {}, "counts": {},
                          "error": str(e), "duration_ms": 0}
            if result["status"] not in ("down", "error"):
                self._detect_changes(site, result)
            result["reason"] = reason
            self.store.add_scan(site_id, result["status"], result, rules["rules_version"])
            status = self._effective_status(result, site["dismissed"])
            self.store.update_site(site_id, last_scan_at=time.time(), last_status=status)
            self._maybe_alert(self.store.site(site_id), result)
            # Newly seen WordPress plugins: hunt their flaws right away, then re-check this site.
            new_slugs = [i["product"][len(intel_mod.PLUGIN_PREFIX):]
                         for i in result.get("facts", {}).get("software", [])
                         if i.get("product", "").startswith(intel_mod.PLUGIN_PREFIX)
                         and i["product"][len(intel_mod.PLUGIN_PREFIX):] not in self.intel.get("plugin_hunted", {})]
            if new_slugs and reason != "plugin intel":
                self.pool.submit(self._plugin_followup, site_id, new_slugs)
        finally:
            self.store.update_site(site_id, scanning=0)

    def _plugin_followup(self, site_id: int, slugs: list[str]):
        try:
            res = self.hunt(plugins_only=slugs, rescan=False)
            if res.get("started"):
                time.sleep(0.2)
                self.scan_async(site_id, "plugin intel")
        except Exception:
            log.exception("plugin follow-up failed")

    def _detect_changes(self, site: dict, result: dict):
        """Report outside code that wasn't on the homepage when monitoring began."""
        facts = result.get("facts", {})
        hosts = facts.get("script_hosts")
        if hosts is None:
            return
        key = f"baseline_scripts:{site['id']}"
        baseline = self.store.get(key)
        if baseline is None:  # first good check = the starting point
            self.store.set(key, sorted(hosts))
            return
        for h in hosts:
            if h in baseline or _domain(h) in COMMON_SCRIPT_DOMAINS:
                continue
            result["findings"].append({
                "key": f"integrity:script:{h}", "severity": "medium", "category": "integrity",
                "title": f"New outside code appeared on your homepage ({h})",
                "detail": f"Your homepage now loads code from {h}, which wasn't there when PatchPulse started "
                          "watching. If you or your developer added a new tool (chat widget, analytics, booking "
                          "system), that's fine - mark this as handled. If nobody did, it could be someone tampering "
                          "with your site, so look into it today.",
                "fix": "Ask whoever manages your website whether they added this. If nobody did, contact your "
                       "hosting company and change your website passwords.",
                "support_ask": f"My homepage has started loading code from {h} and I didn't add it. "
                               "Can you check whether my site has been tampered with?",
                "references": [], "guide": "integrity", "can_dismiss": True})
        from .rules import sort_findings
        result["findings"] = sort_findings(result["findings"])
        result["status"] = recompute_status(result["findings"])

    @staticmethod
    def _effective_status(result: dict, dismissed: list) -> str:
        if result["status"] in ("down", "error"):
            return result["status"]
        active = [f for f in result["findings"] if f["key"] not in dismissed]
        return recompute_status(active)

    def view(self, site_id: int) -> dict | None:
        site = self.store.site(site_id)
        if not site:
            return None
        scan = self.store.latest_scan(site_id)
        if scan:
            for f in scan.get("findings", []):
                f["dismissed"] = f["key"] in site["dismissed"]
        site = {k: v for k, v in site.items() if k not in ("alerted_keys",)}
        return {"site": site, "scan": scan, "history": self.store.scan_history(site_id)}

    # ---------- alerting ----------
    def _maybe_alert(self, site: dict, result: dict):
        cfg = alerts_mod.merged(self.setting("alerts"))
        threshold = SEV_RANK.get(cfg.get("min_severity", "high"), 1)
        findings = {f["key"]: f for f in result.get("findings", [])
                    if SEV_RANK.get(f["severity"], 9) <= threshold and f["key"] not in site["dismissed"]}
        if result["status"] == "error":
            return  # don't flip alert state on our own errors
        previous = set(site["alerted_keys"])
        current = set(findings)
        new = [findings[k] for k in findings if k not in previous]
        resolved = previous - current
        self.store.update_site(site["id"], alerted_keys=sorted(current))
        name = site["label"] or site["url"]
        click = self.setting("public_url") or None
        if new:
            new.sort(key=lambda f: SEV_RANK.get(f["severity"], 9))
            level = new[0]["severity"]
            title = (f"{name}: {new[0]['title']}" if len(new) == 1
                     else f"{name}: {len(new)} new problems found")
            lines = [f"• [{f['severity'].upper()}] {f['title']}" for f in new]
            msg = (f"Website: {site['url']}\n\n" + "\n".join(lines) +
                   "\n\nOpen PatchPulse to see plain-English steps to fix this.")
            res = alerts_mod.send_all(cfg, title, msg, level, click,
                                      extra={"site": site["url"], "findings": [
                                          {"key": f["key"], "severity": f["severity"], "title": f["title"],
                                           "cves": f.get("cves", [])} for f in new]})
            self._log_alert(site, title, res)
        if resolved and cfg.get("notify_resolved", True) and previous:
            title = f"{name}: fixed ✔"
            msg = f"Website: {site['url']}\n\nGood news - {len(resolved)} problem(s) we warned you about are now gone."
            res = alerts_mod.send_all(cfg, title, msg, "resolved", click,
                                      extra={"site": site["url"], "resolved": sorted(resolved)})
            self._log_alert(site, title, res)

    def _log_alert(self, site, title, results):
        if not results:
            self.store.event("finding", title, site["id"])
            return
        ok = [r["channel"] for r in results if r["ok"]]
        bad = [f"{r['channel']} ({r['error']})" for r in results if not r["ok"]]
        msg = title + (f" - alert sent by {', '.join(ok)}" if ok else "") + \
            (f" - FAILED: {'; '.join(bad)}" if bad else "")
        self.store.event("alert" if not bad else "alert_error", msg, site["id"])

    # ---------- background scheduler ----------
    def start(self):
        threading.Thread(target=self._loop, name="scheduler", daemon=True).start()

    def stop(self):
        self._stop.set()
        self.pool.shutdown(wait=False, cancel_futures=True)

    def _loop(self):
        time.sleep(2)
        while True:
            try:
                self.tick()
            except Exception:
                log.exception("scheduler tick failed")
            if self._stop.wait(30):
                break

    def tick(self, now: float | None = None):
        now = now or time.time()
        if now - (self.setting("license_checked_at", 0) or 0) >= LICENSE_CHECK_EVERY:
            try:
                self.refresh_license()
            except Exception:
                log.exception("license refresh failed")
        if not self.active_sites():
            return  # nothing licensed / nothing to watch
        if now - (self.setting("hunt_at", 0) or 0) >= self.hunt_minutes * 60:
            self.hunt_async()
        interval = max(0.25, self.interval_hours) * 3600
        for s in self.active_sites():
            if not s["scanning"] and (s["last_scan_at"] or 0) + interval <= now:
                self.scan_async(s["id"], "scheduled")
        last = self.setting("rules_checked_at", 0) or 0
        if now - last >= RULES_CHECK_EVERY and (self.setting("rules_url") or DEFAULT_RULES_URL):
            try:
                self.update_rules(rescan=True)
            except Exception as e:
                self.store.set("rules_checked_at", now)
                self.store.event("rules_error", f"Couldn't update advisories: {e}")
