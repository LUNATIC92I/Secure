from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..feeds import upsert
from ..models import AuditLog, Device, ProviderConfig
from ..schemas import IndicatorIn, RoleIn
from ..security import audit, require_role

router = APIRouter(prefix="/v1/admin", tags=["admin"])
KNOWN_PROVIDERS = {"virustotal", "webrisk"}


@router.get("/providers")
def list_providers(db: Session = Depends(get_db), _: Device = Depends(require_role("analyst"))):
    rows = {p.name: p for p in db.scalars(select(ProviderConfig)).all()}
    return [
        {
            "name": n,
            "enabled": bool(rows.get(n) and rows[n].enabled),
            "last_success": rows[n].last_success.isoformat() if n in rows and rows[n].last_success else None,
            "last_error": rows[n].last_error if n in rows else None,
        }
        for n in sorted(KNOWN_PROVIDERS)
    ]


@router.put("/providers/{name}")
def toggle_provider(name: str, enabled: bool, db: Session = Depends(get_db), admin: Device = Depends(require_role("admin"))):
    if name not in KNOWN_PROVIDERS:
        raise HTTPException(404, "unknown provider")
    p = db.get(ProviderConfig, name) or ProviderConfig(name=name)
    p.enabled = enabled
    db.add(p)
    audit(db, admin.id, "provider.toggle", f"{name}={enabled}")
    db.commit()
    return {"name": name, "enabled": enabled}


@router.post("/indicators", status_code=201)
def add_indicators(items: list[IndicatorIn], db: Session = Depends(get_db), user: Device = Depends(require_role("analyst"))):
    if len(items) > 5000:
        raise HTTPException(413, "too many indicators in one request")
    added = upsert(db, [i.model_dump() for i in items])
    audit(db, user.id, "indicators.add", f"{added} added")
    db.commit()
    return {"added": added}


@router.put("/devices/{device_id}/role")
def set_role(device_id: str, body: RoleIn, db: Session = Depends(get_db), admin: Device = Depends(require_role("admin"))):
    d = db.get(Device, device_id)
    if d is None:
        raise HTTPException(404, "not found")
    d.role = body.role
    audit(db, admin.id, "device.role", f"{device_id}={body.role}")
    db.commit()
    return {"device_id": device_id, "role": body.role}


@router.get("/audit")
def audit_log(limit: int = 100, db: Session = Depends(get_db), _: Device = Depends(require_role("admin"))):
    rows = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(min(limit, 1000))).all()
    return [{"at": r.at.isoformat(), "actor": r.actor, "action": r.action, "detail": r.detail} for r in rows]
