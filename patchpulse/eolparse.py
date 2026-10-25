"""Parsers for endoflife.date data (MIT-licensed, https://endoflife.date).

Three shapes are accepted, so the app keeps working if one source changes:
  1. API v0 list:   [{"cycle": "8.4", "eol": "2028-12-31" | false, "latest": "8.4.27", ...}, ...]
  2. API v1 object: {"result": {"releases": [{"name": "8.4", "eolFrom": ..., "latest": {"name": ...}}]}}
  3. Product page front matter (products/<slug>.md on GitHub):  releaseCycle / eol / latest lines
All return {cycle: {"eol": "YYYY-MM-DD" | None, "latest": "x.y.z" | None}}.
"""

from __future__ import annotations

import datetime as _dt
import re


def _eol_value(v):
    if v is True:
        return "1970-01-01"  # already end-of-life, date unknown
    if not v or v is False:
        return None
    s = str(v).strip().strip('"\'')
    if s.lower() in ("false", "null", "none", ""):
        return None
    if s.lower() == "true":
        return "1970-01-01"
    try:
        return _dt.date.fromisoformat(s[:10]).isoformat()
    except ValueError:
        return None


def _clean(v):
    if v is None:
        return None
    s = str(v).strip().strip('"\'')
    return s if re.match(r"^\d+(\.\d+)*$", s) else None


def parse(data) -> dict:
    out: dict = {}
    if isinstance(data, list):
        for r in data:
            if isinstance(r, dict) and r.get("cycle") is not None:
                out[str(r["cycle"])] = {"eol": _eol_value(r.get("eol")), "latest": _clean(r.get("latest"))}
        return out
    if isinstance(data, dict):
        rel = (data.get("result") or {}).get("releases") if isinstance(data.get("result"), dict) else None
        if isinstance(rel, list):
            for r in rel:
                latest = r.get("latest")
                if isinstance(latest, dict):
                    latest = latest.get("name")
                eol = r.get("eolFrom")
                if eol is None and r.get("isEol"):
                    eol = True
                out[str(r.get("name"))] = {"eol": _eol_value(eol), "latest": _clean(latest)}
        return out
    if isinstance(data, str):
        return parse_markdown(data)
    return out


def parse_markdown(text: str) -> dict:
    out: dict = {}
    m = re.search(r"^---\s*$(.*?)^---\s*$", text, re.S | re.M)
    body = m.group(1) if m else text
    cur = None
    for line in body.splitlines():
        mm = re.match(r"^\s*-\s*releaseCycle:\s*(.+?)\s*$", line)
        if mm:
            cur = mm.group(1).strip().strip('"\'')
            out[cur] = {"eol": None, "latest": None}
            continue
        if cur is None:
            continue
        mm = re.match(r"^\s+(eol|latest):\s*(.+?)\s*$", line)
        if mm:
            k, v = mm.groups()
            out[cur]["eol" if k == "eol" else "latest"] = _eol_value(v) if k == "eol" else _clean(v)
        elif re.match(r"^\S", line):
            cur = None
    return out
