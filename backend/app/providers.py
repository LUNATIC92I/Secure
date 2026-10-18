"""External reputation providers. Keys live only on the server; the app never sees them.

Only exact values the device chose to share are forwarded: a file hash, or a full URL when
the user enabled detailed URL analysis. Hashed domains are answered from the local
indicator database only (they cannot be reversed to query third parties).
"""

import base64
from datetime import UTC, datetime

import httpx
from sqlalchemy.orm import Session

from .config import get_settings
from .models import ProviderConfig


def _mark(db: Session, name: str, error: str | None) -> None:
    p = db.get(ProviderConfig, name) or ProviderConfig(name=name)
    if error:
        p.last_error = error[:256]
    else:
        p.last_success = datetime.now(UTC)
        p.last_error = None
    db.add(p)


def enabled(db: Session, name: str) -> bool:
    p = db.get(ProviderConfig, name)
    return bool(p and p.enabled)


def virustotal_file(db: Session, sha256: str) -> dict | None:
    key = get_settings().virustotal_api_key
    if not key or not enabled(db, "virustotal"):
        return None
    try:
        r = httpx.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers={"x-apikey": key}, timeout=get_settings().provider_timeout_seconds)
        if r.status_code == 404:
            _mark(db, "virustotal", None)
            return {"provider": "VirusTotal", "verdict": "unknown"}
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        _mark(db, "virustotal", None)
        mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
        verdict = "malicious" if mal >= 3 else ("suspicious" if mal + sus > 0 else "clean")
        return {"provider": "VirusTotal", "verdict": verdict, "detail": f"{mal} malicious / {sus} suspicious engines"}
    except (httpx.HTTPError, KeyError, ValueError) as e:
        _mark(db, "virustotal", type(e).__name__)
        return {"provider": "VirusTotal", "verdict": "error", "detail": "provider unavailable"}


def webrisk_url(db: Session, url: str) -> dict | None:
    key = get_settings().google_webrisk_api_key
    if not key or not enabled(db, "webrisk"):
        return None
    try:
        r = httpx.get(
            "https://webrisk.googleapis.com/v1/uris:search",
            params={"uri": url, "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"], "key": key},
            timeout=get_settings().provider_timeout_seconds,
        )
        r.raise_for_status()
        threat = r.json().get("threat")
        _mark(db, "webrisk", None)
        if threat:
            return {"provider": "Google Web Risk", "verdict": "malicious", "detail": ",".join(threat.get("threatTypes", []))}
        return {"provider": "Google Web Risk", "verdict": "clean"}
    except (httpx.HTTPError, ValueError) as e:
        _mark(db, "webrisk", type(e).__name__)
        return {"provider": "Google Web Risk", "verdict": "error", "detail": "provider unavailable"}


def url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")
