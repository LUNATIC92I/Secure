import hashlib

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import providers
from ..config import get_settings
from ..db import get_db
from ..models import Device, Indicator
from ..ratelimit import limiter
from ..schemas import ReputationIn, ReputationOut
from ..security import current_device

router = APIRouter(prefix="/v1", tags=["reputation"])


def _local(db: Session, body: ReputationIn) -> Indicator | None:
    if body.type == "file_sha256":
        return db.scalar(select(Indicator).where(Indicator.type == "file_sha256", Indicator.value == body.value))
    if body.type == "domain_sha256":
        return db.scalar(select(Indicator).where(Indicator.type == "domain", Indicator.value_sha256 == body.value))
    # Full URL: check URL prefixes and the host's domain hierarchy.
    from urllib.parse import urlsplit

    parts = urlsplit(body.value)
    host = (parts.hostname or "").lower()
    labels = host.split(".")
    for i in range(len(labels) - 1):
        d = ".".join(labels[i:])
        hit = db.scalar(select(Indicator).where(Indicator.type == "domain", Indicator.value_sha256 == hashlib.sha256(d.encode()).hexdigest()))
        if hit:
            return hit
    prefix = (parts.netloc + parts.path).lower()
    for ind in db.scalars(select(Indicator).where(Indicator.type == "url_prefix", Indicator.value.startswith(host))):
        if prefix.startswith(ind.value):
            return ind
    return None


@router.post("/reputation", response_model=ReputationOut)
def reputation(body: ReputationIn, db: Session = Depends(get_db), device: Device = Depends(current_device)):
    if not limiter.allow(f"rep:{device.id}", get_settings().rate_limit_per_minute, 60):
        raise HTTPException(429, "rate limit exceeded")
    hit = _local(db, body)
    sources: list[dict] = []
    if hit:
        sources.append({"provider": "Sentinel indicators", "verdict": "malicious", "detail": f"{hit.family} ({hit.source})"})
    ext = None
    if body.type == "file_sha256":
        ext = providers.virustotal_file(db, body.value)
    elif body.type == "url":
        ext = providers.webrisk_url(db, body.value)
    if ext:
        sources.append(ext)
    db.commit()
    order = ["malicious", "suspicious", "clean", "unknown", "error"]
    best = min(sources, key=lambda s: order.index(s["verdict"])) if sources else {"provider": "Sentinel indicators", "verdict": "unknown"}
    return ReputationOut(verdict=best["verdict"], provider=best["provider"], detail=best.get("detail"), sources=sources)
