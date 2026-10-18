"""Indicator importers for openly licensed feeds.

Usage (inside the container):
    python -m app.feeds urlhaus  path/to/csv_online.txt
    python -m app.feeds stalkerware path/to/ioc.yaml

- URLhaus (abuse.ch): https://urlhaus.abuse.ch/downloads/csv_online/ — CC0.
- Echap stalkerware-indicators: https://github.com/AssoEchap/stalkerware-indicators
  (ioc.yaml) — check the repository licence before redistribution.
Downloading is left to the operator so the backend never fetches feeds implicitly.
"""

import csv
import hashlib
import io
import sys
from urllib.parse import urlsplit

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Indicator

VALID_TYPES = {"package", "cert_sha256", "file_sha256", "domain", "url_prefix"}


def _sha(v: str) -> str:
    return hashlib.sha256(v.lower().encode()).hexdigest()


def upsert(db: Session, items: list[dict]) -> int:
    added = 0
    for it in items:
        t, v = it["type"], it["value"].strip()
        if t not in VALID_TYPES or not v or len(v) > 512:
            continue
        if t in {"domain", "url_prefix"}:
            v = v.lower()
        if db.scalar(select(Indicator).where(Indicator.type == t, Indicator.value == v)):
            continue
        db.add(Indicator(type=t, value=v, value_sha256=_sha(v), family=it.get("family", "unknown")[:128],
                         category=it.get("category", "malware"), source=it["source"], license=it.get("license")))
        added += 1
    db.commit()
    return added


def parse_urlhaus(text: str) -> list[dict]:
    rows = [line for line in text.splitlines() if line and not line.startswith("#")]
    out = []
    for row in csv.reader(io.StringIO("\n".join(rows))):
        if len(row) < 3:
            continue
        url = row[2]
        parts = urlsplit(url)
        if not parts.hostname:
            continue
        prefix = (parts.netloc + parts.path).lower()
        out.append({"type": "url_prefix", "value": prefix, "family": (row[5] if len(row) > 5 else "malware_download") or "malware_download",
                    "category": "malware", "source": "URLhaus (abuse.ch)", "license": "CC0-1.0"})
    return out


def parse_stalkerware(text: str) -> list[dict]:
    out = []
    for app in yaml.safe_load(text) or []:
        name = app.get("name", "stalkerware")
        for pkg in app.get("packages", []) or []:
            out.append({"type": "package", "value": pkg, "family": name, "category": "stalkerware", "source": "Echap stalkerware-indicators"})
        for cert in app.get("certificates", []) or []:
            if isinstance(cert, str) and len(cert) == 64:
                out.append({"type": "cert_sha256", "value": cert.lower(), "family": name, "category": "stalkerware", "source": "Echap stalkerware-indicators"})
        for d in (app.get("websites", []) or []) + (app.get("c2", {}) or {}).get("domains", []):
            out.append({"type": "domain", "value": d, "family": name, "category": "stalkerware", "source": "Echap stalkerware-indicators"})
    return out


if __name__ == "__main__":  # pragma: no cover - CLI
    from .db import get_db

    kind, path = sys.argv[1], sys.argv[2]
    text = open(path, encoding="utf-8").read()
    items = parse_urlhaus(text) if kind == "urlhaus" else parse_stalkerware(text)
    db = next(get_db())
    print(f"imported {upsert(db, items)} new indicators")
