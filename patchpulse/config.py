"""Seller-editable product settings.

Change these BEFORE building the copy you sell. Environment variables with
the same name (prefixed PATCHPULSE_) override them at run time.
"""

import os

# Public half of the LICENSE signing key (private half: seller kit / license server only).
PUBLIC_KEY_HEX = os.environ.get(
    "PATCHPULSE_PUBLIC_KEY", "00ae0f81242fa8ee5eadd0a7de12874a9979e27ba4fb1254099d021d77f9f312")

# Public half of the THREAT-FEED signing key (private half: seller kit / GitHub Actions secret only).
# Kept separate so a compromised license server can't push fake threat data, and vice versa.
RULES_PUBLIC_KEY_HEX = os.environ.get(
    "PATCHPULSE_RULES_PUBLIC_KEY", "247761e24e31e10629359679aa6b565644d7e42c5ced8bbc2b52c8f1c853f255")

# There is no free tier: monitoring requires a valid license.
# Online activation server (see seller kit license_server.py). Empty = offline license keys only.
ACTIVATION_URL = os.environ.get("PATCHPULSE_ACTIVATION_URL", "https://license.patchpulsehq.com")

# Where the "Buy" button sends people.
BUY_URL = os.environ.get("PATCHPULSE_BUY_URL", "https://patchpulsehq.com/pricing")

# Signed curated advisories (plain-English write-ups for big threats like PHP2Shell).
RULES_URL = os.environ.get("PATCHPULSE_RULES_URL", "https://feed.patchpulsehq.com/rules.json")

# Signed central threat-intel feed built by the hunt hub (GitHub Actions, hourly).
# Empty = every install hunts directly from CISA / NVD / endoflife.date / wordpress.org.
INTEL_URL = os.environ.get("PATCHPULSE_INTEL_URL", "https://feed.patchpulsehq.com/intel.json")

# Shown in the Help screen. Leave empty to hide.
SUPPORT_EMAIL = os.environ.get("PATCHPULSE_SUPPORT_EMAIL", "support@patchpulsehq.com")

# Website-count limits per plan name written into license keys (0 = unlimited).
PLANS = {"personal": 5, "pro": 25, "agency": 0, "business": 0}

# How often the threat hunt runs, in minutes, and the default website re-check interval in hours.
HUNT_MINUTES = int(os.environ.get("PATCHPULSE_HUNT_MINUTES", "60"))
DEFAULT_SCAN_HOURS = float(os.environ.get("PATCHPULSE_SCAN_HOURS", "3"))
