# PatchPulse threat feed

Every hour a GitHub Action checks public sources (CISA Known Exploited Vulnerabilities, the NIST National
Vulnerability Database, the CVE Program, endoflife.date and WordPress.org), signs the result, and publishes it
at https://feed.patchpulsehq.com/intel.json together with curated advisories at /rules.json. PatchPulse apps
verify the signature before using either file.

The feed holds only public vulnerability data. The signing key is a repository secret and is never stored here.

This product uses data from the NVD API but is not endorsed or certified by the NVD.
PatchPulse is independent and not affiliated with or endorsed by CISA, DHS, NIST, MITRE, or WordPress.
CVE is a registered trademark of The MITRE Corporation. CVE records are used under the CVE Program terms of use.

© FPH LLC. The PatchPulse source code in this repository is proprietary; see LICENSE.txt.
