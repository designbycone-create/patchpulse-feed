"""Active threat hunting.

Continuously pulls from authoritative public sources and turns them into
version-matchable threat data for every piece of software PatchPulse finds
on a customer's websites:

  * CISA Known Exploited Vulnerabilities (KEV) catalog - flaws attackers are
    using right now (CC0 public domain).
  * NIST National Vulnerability Database (NVD) API 2.0 - affected version
    ranges and severity for every CVE. ("This product uses data from the NVD
    API but is not endorsed or certified by the NVD.")
  * endoflife.date - support end dates and latest patch release per branch (MIT).
  * wordpress.org - latest version of each detected WordPress plugin.

Each source has a fallback, every source is optional (a failure never breaks
scanning), and results are cached in the local database. The same code runs in
"hub mode" (`patchpulse hunt`) to build one signed feed for all customers.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from . import USER_AGENT, eolparse

log = logging.getLogger("patchpulse.intel")

KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EOL_API = "https://endoflife.date/api/{slug}.json"
EOL_FALLBACK = "https://raw.githubusercontent.com/endoflife-date/endoflife.date/master/products/{slug}.md"
WP_PLUGIN_API = ("https://api.wordpress.org/plugins/info/1.2/?action=plugin_information"
                 "&request%5Bslug%5D={slug}&request%5Bfields%5D%5Bsections%5D=0")
CVE5_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}/{cve}.json"
NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/{cve}"
KEV_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
NVD_NOTICE = "This product uses data from the NVD API but is not endorsed or certified by the NVD."

# What we can fingerprint from outside, and how each product is named in each source.
PRODUCTS = {
    "php": {"display": "PHP", "cpes": [("php", "php")], "eol": "php",
            "kev": [("php", "php"), ("php group", "php"), ("php", "fastcgi process manager (fpm)")],
            "names": ["php"]},
    "wordpress": {"display": "WordPress", "cpes": [("wordpress", "wordpress")], "eol": "wordpress",
                  "kev": [("wordpress", "core")], "names": ["wordpress"]},
    "apache": {"display": "Apache web server", "cpes": [("apache", "http_server")], "eol": "apache-http-server",
               "kev": [("apache", "http server"), ("apache", "apache")], "names": ["apache http server", "http_server"]},
    "nginx": {"display": "nginx web server", "cpes": [("f5", "nginx"), ("nginx", "nginx"), ("f5", "nginx_open_source")],
              "eol": "nginx", "kev": [], "names": ["nginx", "nginx open source"]},
    "drupal": {"display": "Drupal", "cpes": [("drupal", "drupal")], "eol": "drupal",
               "kev": [("drupal", "core"), ("drupal", "drupal core")], "names": ["drupal core", "drupal"]},
    "joomla": {"display": "Joomla", "cpes": [("joomla", "joomla\\!"), ("joomla", "joomla!")], "eol": "joomla",
               "kev": [("joomla!", "joomla!")], "names": ["joomla!", "joomla"]},
}
PLUGIN_PREFIX = "wp-plugin:"
MAX_FETCH = 25 * 1024 * 1024
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,80}$")


# ---------------------------------------------------------------- versions

def vt(s) -> tuple:
    """'8.4.27' -> (8, 4, 27); '10.2.1.14-75sv' -> (10, 2, 1, 14). Empty tuple if no digits."""
    m = re.match(r"\s*v?(\d+(?:\.\d+)*)", str(s or ""))
    return tuple(int(x) for x in m.group(1).split(".")) if m else ()


def vcmp(a: tuple, b: tuple) -> int:
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def in_range(version, r: dict) -> bool:
    v = vt(version)
    if not v:
        return False
    if r.get("exact"):
        return vcmp(v, vt(r["exact"])) == 0
    if r.get("si") and vcmp(v, vt(r["si"])) < 0:
        return False
    if r.get("se") and vcmp(v, vt(r["se"])) <= 0:
        return False
    if r.get("ei") and vcmp(v, vt(r["ei"])) > 0:
        return False
    if r.get("ee") and vcmp(v, vt(r["ee"])) >= 0:
        return False
    return True


def fixed_version(version, r: dict) -> str | None:
    """Lowest version that is NOT in this range and is above `version`, when knowable."""
    return r.get("ee") or None


def cycle_for(version, cycles: dict) -> str | None:
    """Find the release branch a version belongs to ('8.4.20' -> '8.4'; Joomla '5.1.2' -> '5')."""
    v = vt(version)
    best = None
    for c in cycles:
        cv = vt(c)
        if cv and v[:len(cv)] == cv and (best is None or len(cv) > len(vt(best))):
            best = c
    return best


# ---------------------------------------------------------------- source parsing

def _cpe_parts(criteria: str):
    # cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    parts = re.split(r"(?<!\\):", criteria)
    return parts + [""] * (13 - len(parts))


def plugin_slug_variants(slug: str) -> set:
    return {slug, slug.replace("-", "_"), slug.replace("_", "-")}


def _score(cve: dict):
    """(score, cvss_severity, exploited_per_ssvc)"""
    best = None
    exploited = False
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        for m in (cve.get("metrics") or {}).get(key, []) or []:
            d = m.get("cvssData") or {}
            s = d.get("baseScore")
            if isinstance(s, (int, float)):
                prim = m.get("type") == "Primary"
                if best is None or (prim and not best[2]):
                    best = (float(s), (d.get("baseSeverity") or m.get("baseSeverity") or "").upper(), prim)
        if best:
            break
    for m in (cve.get("metrics") or {}).get("ssvcV203", []) or []:
        for opt in (m.get("ssvcData") or {}).get("options", []) or []:
            for k, val in opt.items():
                if k.lower() == "exploitation" and str(val).lower() == "active":
                    exploited = True
    return (best[0] if best else None), (best[1] if best else ""), exploited


def parse_cve(cve: dict, kev_entry: dict | None = None, plugin_slugs=()) -> list[dict]:
    """Turn one NVD CVE record into zero or more product vulnerability records."""
    cid = cve.get("id") or cve.get("cveId")
    if not cid or cve.get("vulnStatus") == "Rejected":
        return []
    score, cvss_sev, ssvc_active = _score(cve)
    found: dict[str, dict] = {}

    def add(product, rng, platform):
        rec = found.setdefault(product, {"ranges": [], "platforms": set()})
        if rng not in rec["ranges"]:
            rec["ranges"].append(rng)
        if platform:
            rec["platforms"].add(platform)

    desc = " ".join(d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en")
    desc_slugs = set(re.findall(r"\(([a-z0-9][a-z0-9-]{1,80})\)\s+(?:plugin|WordPress plugin)", desc, re.I))
    desc_slugs = {s.lower() for s in desc_slugs}

    for conf in cve.get("configurations", []) or []:
        nodes = conf.get("nodes", []) or []
        platform = None
        if (conf.get("operator") or "").upper() == "AND":
            for n in nodes:
                for m in n.get("cpeMatch", []) or []:
                    if not m.get("vulnerable"):
                        p = _cpe_parts(m.get("criteria", ""))
                        if p[2] == "o":
                            platform = p[4].replace("_", " ")
        for n in nodes:
            if n.get("negate"):
                continue
            for m in n.get("cpeMatch", []) or []:
                if not m.get("vulnerable"):
                    continue
                p = _cpe_parts(m.get("criteria", ""))
                if p[2] != "a":
                    continue
                vendor, prod, ver, target = p[3].lower(), p[4].lower(), p[5], p[10].lower()
                rng = {k: m[v] for k, v in (("si", "versionStartIncluding"), ("se", "versionStartExcluding"),
                                            ("ei", "versionEndIncluding"), ("ee", "versionEndExcluding")) if m.get(v)}
                if ver not in ("*", "-", ""):
                    rng = {"exact": ver.replace("\\", "")}
                product = None
                for key, info in PRODUCTS.items():
                    if (vendor, prod) in info["cpes"]:
                        product = key
                if product is None and target == "wordpress":
                    for slug in set(plugin_slugs) | desc_slugs:
                        if prod in plugin_slug_variants(slug) or slug in desc_slugs:
                            product = PLUGIN_PREFIX + slug
                            break
                if product:
                    add(product, rng, platform)

    src = "nvd"
    if not found:  # fresh CVEs: NVD hasn't analysed yet - use the vendor's own "affected" data
        src = "cna"
        for a in cve.get("affected", []) or []:
            for ad in a.get("affectedData", []) or []:
                vend, prod = str(ad.get("vendor", "")).lower(), str(ad.get("product", "")).lower()
                product = None
                for key, info in PRODUCTS.items():
                    if prod in info["names"] or (vend, prod) in info["kev"]:
                        product = key
                if product is None:
                    for slug in set(plugin_slugs) | desc_slugs:
                        if prod.replace(" ", "-") == slug or slug in desc_slugs:
                            product = PLUGIN_PREFIX + slug
                if not product:
                    continue
                plats = ad.get("platforms") or []
                for v in ad.get("versions", []) or []:
                    if v.get("status") != "affected":
                        continue
                    rng = cna_range(v)
                    if rng:
                        add(product, rng, plats[0] if len(plats) == 1 else None)

    kev = bool(kev_entry) or bool(cve.get("cisaExploitAdd"))
    out = []
    for product, rec in found.items():
        out.append({
            "id": cid, "product": product, "ranges": rec["ranges"], "src": src,
            "platform": sorted(rec["platforms"])[0] if len(rec["platforms"]) == 1 else None,
            "score": score, "cvss": cvss_sev, "kev": kev, "exploited": kev or ssvc_active,
            "kev_added": (kev_entry or {}).get("dateAdded") or cve.get("cisaExploitAdd"),
            "ransomware": (kev_entry or {}).get("knownRansomwareCampaignUse") == "Known",
            "name": (kev_entry or {}).get("vulnerabilityName") or cve.get("cisaVulnerabilityName"),
            "published": (cve.get("published") or "")[:10],
            "modified": (cve.get("lastModified") or "")[:19],
        })
    return out


_NUM = re.compile(r"\d+(?:\.\d+)+|\d+")


def _nums(text) -> list[str]:
    return _NUM.findall(str(text or ""))


def cna_range(v: dict) -> dict:
    """Normalise a vendor 'affected' entry. Vendors write versions many ways:
    '8.1.*' + lessThan, '0' + lessThan, '2.4.17 to 2.4.38', '9.0 versions prior to 9.0.8',
    'Apache HTTP Server 2.4.49', 'unspecified'. Returns {} when nothing usable."""
    raw = str(v.get("version", "")).strip()
    low = raw.lower()
    nums = _nums(raw)
    rng: dict = {}
    m = re.search(r"(\d+(?:\.\d+)+)\s*(?:to|through|-)\s*(\d+(?:\.\d+)+)", raw)
    if m:
        return {"si": m.group(1), "ei": m.group(2)}
    m = re.search(r"(?:prior to|before|earlier than|<)\s*(\d+(?:\.\d+)+)", low)
    if m:
        rng["ee"] = m.group(1)
        start = [n for n in nums if n != m.group(1)]
        if start:
            rng["si"] = start[0]
        return rng
    m = re.search(r"(?:and earlier|or earlier|<=)\s*", low)
    if m and nums:
        return {"ei": nums[-1]}
    lt = v.get("lessThan") and (_nums(v["lessThan"]) or [None])[0]
    le = v.get("lessThanOrEqual") and (_nums(v["lessThanOrEqual"]) or [None])[0]
    start = None if (not nums or low in ("0", "n/a", "unspecified", "*", "all")) else nums[0]
    if start == "0":
        start = None
    if lt or le:
        if start:
            rng["si"] = start
        if lt:
            rng["ee"] = lt
        else:
            rng["ei"] = le
        return rng
    if nums and "*" not in raw and "x" not in low.replace(" ", "")[-2:]:
        best = max(nums, key=lambda n: n.count("."))
        if best.count(".") >= 2:
            return {"exact": best}
    return {}


def cve5_url(cve_id: str) -> str:
    _, year, num = cve_id.split("-")
    return CVE5_URL.format(year=year, bucket=f"{int(num) // 1000}xxx", cve=cve_id)


def cve5_to_nvd(d: dict) -> dict:
    """Convert an official CVE Program (cvelistV5) record into the NVD shape parse_cve reads."""
    meta = d.get("cveMetadata") or {}
    cna = (d.get("containers") or {}).get("cna") or {}
    adps = (d.get("containers") or {}).get("adp") or []
    metrics, ssvc = {}, []
    for m in (cna.get("metrics") or []) + [m for a in adps for m in (a.get("metrics") or [])]:
        for key, nkey in (("cvssV3_1", "cvssMetricV31"), ("cvssV3_0", "cvssMetricV30"), ("cvssV4_0", "cvssMetricV40")):
            if isinstance(m.get(key), dict) and nkey not in metrics:
                metrics[nkey] = [{"type": "Secondary", "cvssData": {"baseScore": m[key].get("baseScore"),
                                                                    "baseSeverity": m[key].get("baseSeverity")}}]
        other = m.get("other") or {}
        if other.get("type") == "ssvc":
            ssvc.append({"ssvcData": {"options": (other.get("content") or {}).get("options", [])}})
    if ssvc:
        metrics["ssvcV203"] = ssvc
    return {"id": meta.get("cveId"), "published": meta.get("datePublished", ""),
            "lastModified": meta.get("dateUpdated", ""), "vulnStatus": "Rejected" if meta.get("state") == "REJECTED"
            else "CNA", "descriptions": cna.get("descriptions") or [], "metrics": metrics,
            "affected": [{"affectedData": cna.get("affected") or []}]}


def kev_product(entry: dict) -> str | None:
    vp = (str(entry.get("vendorProject", "")).lower(), str(entry.get("product", "")).lower())
    for key, info in PRODUCTS.items():
        if vp in info["kev"]:
            return key
    if vp[0] == "wordpress" and "plugin" in vp[1]:
        return PLUGIN_PREFIX + "?"
    return None


def severity_of(v: dict) -> str:
    if v.get("exploited"):
        return "critical"
    s = v.get("score")
    if s is None:
        return "medium"
    return "high" if s >= 9.0 else "medium" if s >= 7.0 else "low"


# ---------------------------------------------------------------- HTTP

def _ctx():
    ctx = ssl.create_default_context()
    try:
        import certifi  # type: ignore
        ctx.load_verify_locations(certifi.where())
    except Exception:
        pass
    return ctx


def http_get(url: str, headers: dict | None = None, timeout: float = 30.0) -> bytes:
    h = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    h.update(headers or {})
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:
        data = r.read(MAX_FETCH + 1)
    if len(data) > MAX_FETCH:
        raise ValueError("response too large")
    return data


def http_json(url: str, headers: dict | None = None, timeout: float = 30.0):
    return json.loads(http_get(url, headers, timeout).decode("utf-8"))


# ---------------------------------------------------------------- the hunter

def empty_intel() -> dict:
    return {"schema": 1, "generated": None, "sources": {}, "products": {}, "plugins": {}, "vulns": {},
            "kev_count": 0, "kev_version": None, "nvd_checked_until": None, "plugin_hunted": {}}


def load_snapshot() -> dict:
    from pathlib import Path
    p = Path(__file__).parent / "data" / "eol_snapshot.json"
    try:
        return json.loads(p.read_text("utf-8"))["products"]
    except Exception:
        return {}


class Hunter:
    """Runs one hunt over all sources and updates the intel dict in place.

    `get_json(url, headers)` and `sleep(seconds)` are injectable for tests and hub mode.
    """

    def __init__(self, intel: dict | None = None, *, nvd_api_key: str = "", get_json=None, get_text=None,
                 sleep=time.sleep, now=None, backfill_days: int = 119):
        self.intel = intel or empty_intel()
        for k, v in empty_intel().items():
            self.intel.setdefault(k, v)
        self.key = nvd_api_key.strip()
        self.get_json = get_json or http_json
        self.get_text = get_text or (lambda u: http_get(u, {"Accept": "text/plain"}).decode("utf-8", "replace"))
        self.sleep = sleep
        self.now = now or (lambda: _dt.datetime.now(_dt.timezone.utc))
        self.backfill_days = backfill_days
        self._last_nvd = 0.0
        self.new_ids: set = set()
        self.errors: list[str] = []

    # --- helpers
    def _src(self, name, ok, **kw):
        self.intel["sources"][name] = {"ok": ok, "at": self.now().isoformat(timespec="seconds"), **kw}

    def _nvd(self, params: dict) -> dict:
        gap = 0.7 if self.key else 6.5  # NVD public rate limit: 5 requests / 30 s without a key
        wait = self._last_nvd + gap - time.monotonic()
        if wait > 0:
            self.sleep(wait)
        url = NVD_API + "?" + urllib.parse.urlencode(params, safe=":*")
        try:
            return self.get_json(url, {"apiKey": self.key} if self.key else None)
        finally:
            self._last_nvd = time.monotonic()

    def _nvd_paged(self, params: dict, max_pages: int = 10):
        start = 0
        for _ in range(max_pages):
            data = self._nvd({**params, "resultsPerPage": 200, "startIndex": start})
            vulns = data.get("vulnerabilities", []) or []
            for item in vulns:
                yield item.get("cve") or item
            start += len(vulns)
            if not vulns or start >= int(data.get("totalResults", 0)):
                break

    def _store(self, records: list[dict]):
        for r in records:
            key = f"{r['id']}|{r['product']}"
            old = self.intel["vulns"].get(key)
            if old is None:
                self.new_ids.add(key)
            elif old.get("exploited") != r.get("exploited") or old.get("ranges") != r.get("ranges"):
                self.new_ids.add(key)  # newly exploited or ranges changed = news
            self.intel["vulns"][key] = r

    # --- sources
    def hunt_kev(self) -> dict:
        data, err = None, None
        for url in KEV_URLS:
            try:
                data = self.get_json(url)
                if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list):
                    break
                data = None
            except Exception as e:
                err = e
        if not data:
            self._src("kev", False, error=str(err)[:200])
            self.errors.append(f"CISA exploited-flaws list: {err}")
            return {}
        self.intel["kev_count"] = len(data["vulnerabilities"])
        self.intel["kev_version"] = data.get("catalogVersion")
        relevant = {}
        for e in data["vulnerabilities"]:
            p = kev_product(e)
            if p:
                relevant[e["cveID"]] = e
        self._src("kev", True, version=data.get("catalogVersion"), relevant=len(relevant))
        return relevant

    def hunt_kev_details(self, relevant: dict, plugin_slugs=()):
        """Fetch version ranges for exploited flaws we don't have yet (or whose status changed)."""
        have = {k.split("|")[0]: v for k, v in self.intel["vulns"].items()}
        known_ids = set(self.intel.setdefault("kev_seen", []))
        nvd_down = False
        for cid, entry in relevant.items():
            if cid in known_ids and cid in have and have[cid].get("kev") and have[cid].get("src") == "nvd":
                continue
            if not nvd_down:
                try:
                    data = self._nvd({"cveId": cid})
                    for item in data.get("vulnerabilities", []) or []:
                        self._store(parse_cve(item.get("cve") or item, entry, plugin_slugs))
                    known_ids.add(cid)
                    continue
                except Exception as e:
                    self.errors.append(f"NVD detail {cid}: {e} - using the CVE Program's records instead")
                    nvd_down = True
            if cid in have:
                continue
            try:  # NVD unreachable: official CVE Program record (vendor's own affected versions)
                self._store(parse_cve(cve5_to_nvd(self.get_json(cve5_url(cid))), entry, plugin_slugs))
            except Exception as e:
                self.errors.append(f"CVE record {cid}: {e}")
        self.intel["kev_seen"] = sorted(known_ids)

    def hunt_nvd(self, plugin_slugs=()):
        """New or changed CVEs for each tracked product since the last hunt."""
        end = self.now()
        last = self.intel.get("nvd_checked_until")
        start = (_dt.datetime.fromisoformat(last) - _dt.timedelta(hours=2)) if last else \
            end - _dt.timedelta(days=self.backfill_days)
        start = max(start, end - _dt.timedelta(days=119))
        fmt = lambda d: d.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        ok = True
        count = 0
        for key, info in PRODUCTS.items():
            for vendor, prod in info["cpes"][:1] if key != "nginx" else info["cpes"][:2]:
                try:
                    for cve in self._nvd_paged({"virtualMatchString": f"cpe:2.3:a:{vendor}:{prod}",
                                                "lastModStartDate": fmt(start), "lastModEndDate": fmt(end),
                                                "noRejected": ""}):
                        self._store(parse_cve(cve, None, plugin_slugs))
                        count += 1
                except Exception as e:
                    ok = False
                    self.errors.append(f"NVD {key}: {e}")
        if ok:
            self.intel["nvd_checked_until"] = end.isoformat(timespec="seconds")
        self._src("nvd", ok, checked=count)

    def hunt_plugins(self, slugs):
        """For each detected WordPress plugin: latest version + its known flaws."""
        slugs = [s for s in sorted(set(slugs)) if _SLUG_RE.match(s)]
        fmt = lambda d: d.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        now = self.now()
        for slug in slugs:
            pinfo = self.intel["plugins"].setdefault(slug, {})
            try:
                if not pinfo.get("at") or (now - _dt.datetime.fromisoformat(pinfo["at"])).total_seconds() > 12 * 3600:
                    d = self.get_json(WP_PLUGIN_API.format(slug=urllib.parse.quote(slug)))
                    if isinstance(d, dict) and d.get("version"):
                        pinfo.update(latest=str(d["version"])[:30], name=str(d.get("name", slug))[:120],
                                     closed=False)
                    elif isinstance(d, dict) and d.get("error"):
                        pinfo.update(closed="closed" in str(d.get("error")).lower(), latest=None)
                    pinfo["at"] = now.isoformat(timespec="seconds")
            except Exception as e:
                self.errors.append(f"wordpress.org {slug}: {e}")
            try:
                last = self.intel["plugin_hunted"].get(slug)
                params = {"keywordSearch": slug, "noRejected": ""}
                if last:
                    start = max(_dt.datetime.fromisoformat(last) - _dt.timedelta(hours=2),
                                now - _dt.timedelta(days=119))
                    params.update(lastModStartDate=fmt(start), lastModEndDate=fmt(now))
                for cve in self._nvd_paged(params, max_pages=5):
                    self._store(parse_cve(cve, None, [slug]))
                self.intel["plugin_hunted"][slug] = now.isoformat(timespec="seconds")
            except Exception as e:
                self.errors.append(f"NVD plugin {slug}: {e}")

    def hunt_eol(self):
        snap = load_snapshot()
        ok_all = True
        for key, info in PRODUCTS.items():
            cycles = None
            try:
                cycles = eolparse.parse(self.get_json(EOL_API.format(slug=info["eol"])))
            except Exception:
                try:
                    cycles = eolparse.parse_markdown(self.get_text(EOL_FALLBACK.format(slug=info["eol"])))
                except Exception as e:
                    ok_all = False
                    self.errors.append(f"end-of-life data {key}: {e}")
            if cycles:
                self.intel["products"][key] = {"cycles": cycles, "source": "live"}
            elif key not in self.intel["products"] and snap.get(key):
                self.intel["products"][key] = {"cycles": snap[key], "source": "built-in snapshot"}
        self._src("eol", ok_all)

    # --- one full hunt
    def run(self, plugin_slugs=(), *, skip_core: bool = False) -> dict:
        self.new_ids = set()
        self.errors = []
        if not skip_core:
            relevant = self.hunt_kev()
            self.hunt_eol()
            self.hunt_kev_details(relevant, plugin_slugs)
            self.hunt_nvd(plugin_slugs)
        if plugin_slugs:
            self.hunt_plugins(plugin_slugs)
        self.intel["generated"] = self.now().isoformat(timespec="seconds")
        self.intel["errors"] = self.errors[-10:]
        return {"new": sorted(self.new_ids), "errors": self.errors}


def merge_hub(local: dict, hub: dict) -> dict:
    """Merge a signed central feed into local intel (hub wins on conflicts)."""
    for k in ("products", "vulns"):
        local.setdefault(k, {}).update(hub.get(k) or {})
    for k in ("kev_count", "kev_version", "nvd_checked_until"):
        if hub.get(k):
            local[k] = hub[k]
    local.setdefault("sources", {})["hub"] = {"ok": True, "at": _dt.datetime.now(_dt.timezone.utc)
                                              .isoformat(timespec="seconds"), "generated": hub.get("generated")}
    return local


def validate_intel(d: dict) -> dict:
    if not isinstance(d, dict) or d.get("schema") != 1:
        raise ValueError("unsupported intel schema")
    if not isinstance(d.get("vulns", {}), dict) or not isinstance(d.get("products", {}), dict):
        raise ValueError("bad intel structure")
    for key, v in d["vulns"].items():
        if not re.match(r"^CVE-\d{4}-\d{4,}\|", key):
            raise ValueError(f"bad vuln id {key[:40]}")
        if not isinstance(v.get("ranges"), list):
            raise ValueError("bad ranges")
    return d


def vulns_for(product: str, version: str, intel: dict) -> list[dict]:
    out = []
    for v in (intel.get("vulns") or {}).values():
        if v.get("product") == product and any(in_range(version, r) for r in v.get("ranges", [])):
            out.append(v)
    return out
