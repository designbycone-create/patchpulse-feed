"""PatchPulse command line.

  patchpulse                      start the app and open it in your browser
  patchpulse serve [--host H] [--port P] [--no-browser] [--data DIR]
  patchpulse scan mysite.com [--json]   one-off check (exit code 2=critical, 1=warning, 0=ok; needs a license)
  patchpulse activate PP1-...     enter / activate a license key
  patchpulse hunt --out intel.json [--sign-key FILE]   build the signed central threat feed (hub mode)
  patchpulse reset-password       forget the password (you'll set a new one in the browser)
  patchpulse version
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from . import APP_NAME, __version__


def default_data_dir() -> Path:
    env = os.environ.get("PATCHPULSE_DATA")
    if env:
        return Path(env)
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA", Path.home())) / APP_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "patchpulse"


ICON = {"critical": "[!!] CRITICAL", "high": "[! ] HIGH    ", "medium": "[- ] MEDIUM  ",
        "low": "[. ] LOW     ", "info": "[i ] INFO    "}


def _engine(data_dir):
    from .engine import Engine
    from .store import Store
    return Engine(Store(data_dir / "patchpulse.db"))


def cmd_scan(args, data_dir) -> int:
    from .netsafe import UnsafeTarget, normalize_site_url
    from .scanner import scan_site
    eng = _engine(data_dir)
    st = eng.license_status()
    if st["state"] != "active":
        print(f"PatchPulse needs an active license to check websites. {st['message']}\n"
              "Enter your key with:  patchpulse activate YOUR-KEY", file=sys.stderr)
        return 4
    try:
        url = normalize_site_url(args.url)
        if not eng.setting("hunt_at"):
            eng.hunt(rescan=False)
        res = scan_site(url, eng.rules, allow_private=args.allow_private, intel=eng.intel)
    except (ValueError, UnsafeTarget) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 3
    if args.json:
        print(json.dumps({"url": url, **res}, indent=2))
    else:
        verdict = {"critical": "AT RISK - fix now", "warning": "Needs attention", "ok": "Looks good",
                   "down": "Website not reachable"}[res["status"]]
        print(f"\n{APP_NAME} check of {url}\nResult: {verdict}\n")
        f = res["facts"]
        print(f"  PHP version:      {f.get('php_version') or 'hidden'}")
        if f.get("wordpress"):
            print(f"  WordPress:        {f.get('wordpress_version') or 'yes (version hidden)'}")
        if f.get("cert_days_left") is not None:
            print(f"  Certificate:      expires in {f['cert_days_left']} days")
        print()
        for fd in res["findings"]:
            print(f"  {ICON.get(fd['severity'], fd['severity'])}  {fd['title']}")
            print(f"        Fix: {fd['fix']}\n")
        if not res["findings"]:
            print("  No problems found.\n")
    return {"critical": 2, "down": 2, "warning": 1}.get(res["status"], 0)


def cmd_hunt(args) -> int:
    from . import intel as intel_mod, licensing
    state = None
    if args.state and Path(args.state).exists():
        try:
            env = json.loads(Path(args.state).read_text("utf-8"))
            state = intel_mod.validate_intel(env.get("intel", env))  # also drops stale unbounded entries
        except Exception:
            state = None
    h = intel_mod.Hunter(state, nvd_api_key=args.nvd_key)
    slugs = [s.strip() for s in args.plugins.split(",") if s.strip()]
    res = h.run(slugs)
    data = intel_mod.validate_intel(h.intel)
    out = data
    if args.sign_key:
        out = licensing.sign_feed(Path(args.sign_key).read_text().strip(), "intel", data)
    Path(args.out).write_text(json.dumps(out, separators=(",", ":")), "utf-8")
    print(f"Hunt done: {len(data['vulns'])} flaws tracked, {len(res['new'])} new/changed, "
          f"{len(res['errors'])} source errors.")
    for e in res["errors"][:10]:
        print("  source error:", e)
    return 0 if len(res["errors"]) < 5 else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="patchpulse", description=f"{APP_NAME} - website exposure monitor")
    p.add_argument("--data", help="folder to keep PatchPulse's data in")
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("serve", help="run the app")
    s.add_argument("--host", default=os.environ.get("PATCHPULSE_HOST", "127.0.0.1"))
    s.add_argument("--port", type=int, default=int(os.environ.get("PATCHPULSE_PORT", "8765")))
    s.add_argument("--no-browser", action="store_true")
    sc = sub.add_parser("scan", help="check one website and print the result")
    sc.add_argument("url")
    sc.add_argument("--json", action="store_true")
    sc.add_argument("--allow-private", action="store_true", help=argparse.SUPPRESS)
    ac = sub.add_parser("activate", help="enter a license key")
    ac.add_argument("key")
    hu = sub.add_parser("hunt", help="hub mode: run a full threat hunt and write the (signed) feed")
    hu.add_argument("--out", required=True)
    hu.add_argument("--state", help="previous feed to continue from (makes hunts incremental)")
    hu.add_argument("--sign-key", help="file holding the PRIVATE threat-feed signing key (hex)")
    hu.add_argument("--plugins", default="", help="comma-separated WordPress plugin slugs to cover")
    hu.add_argument("--nvd-key", default=os.environ.get("NVD_API_KEY", ""))
    sub.add_parser("reset-password")
    sub.add_parser("version")
    args = p.parse_args(argv)

    logging.basicConfig(level=os.environ.get("PATCHPULSE_LOG", "WARNING"),
                        format="%(asctime)s %(levelname)s %(message)s")
    data_dir = Path(args.data) if args.data else default_data_dir()

    if args.cmd == "version":
        print(__version__)
        return 0
    if args.cmd == "scan":
        return cmd_scan(args, data_dir)
    if args.cmd == "activate":
        from .licensing import LicenseError
        try:
            lic = _engine(data_dir).set_license(args.key)
        except LicenseError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 3
        print(f"License activated: {lic.get('plan')} plan for {lic.get('name')}.")
        return 0
    if args.cmd == "hunt":
        return cmd_hunt(args)
    if args.cmd == "reset-password":
        from .store import Store
        st = Store(data_dir / "patchpulse.db")
        st.set("auth", None)
        st.drop_all_sessions()
        print("Password cleared. Start PatchPulse and choose a new password in your browser.")
        return 0

    from .server import serve
    host = getattr(args, "host", os.environ.get("PATCHPULSE_HOST", "127.0.0.1"))
    port = getattr(args, "port", int(os.environ.get("PATCHPULSE_PORT", "8765")))
    no_browser = getattr(args, "no_browser", False) or os.environ.get("PATCHPULSE_NO_BROWSER") == "1"
    try:
        serve(data_dir, host=host, port=port, open_browser=not no_browser)
    except OSError as e:
        print(f"\n{APP_NAME} couldn't start: {e}\n", file=sys.stderr)
        if sys.stdin and sys.stdin.isatty():
            input("Press Enter to close this window...")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
