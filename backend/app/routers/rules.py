from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Device, Indicator, RulePackVersion
from ..schemas import PublishIn
from ..security import audit, current_device, require_role
from ..signing import SigningUnavailable, build_pack, public_key_b64, sign

router = APIRouter(prefix="/v1", tags=["rules"])


@router.get("/rules/latest")
def latest(db: Session = Depends(get_db), _: Device = Depends(current_device)):
    """Signed pack: the app verifies the Ed25519 signature against its pinned keys."""
    pack = db.scalar(select(RulePackVersion).order_by(RulePackVersion.version.desc()).limit(1))
    if pack is None:
        raise HTTPException(404, "no rule pack published")
    return {"version": pack.version, "body": pack.body, "signature": pack.signature}


@router.get("/rules/versions")
def versions(db: Session = Depends(get_db), _: Device = Depends(require_role("analyst"))):
    rows = db.scalars(select(RulePackVersion).order_by(RulePackVersion.version.desc())).all()
    return [{"version": r.version, "created_at": r.created_at.isoformat(), "created_by": r.created_by} for r in rows]


@router.post("/admin/rules/publish", status_code=201)
def publish(body: PublishIn, db: Session = Depends(get_db), admin: Device = Depends(require_role("admin"))):
    current = db.scalar(select(func.max(RulePackVersion.version))) or 0
    indicators = [
        {
            k: v
            for k, v in {"type": i.type, "value": i.value, "family": i.family, "category": i.category, "source": i.source, "license": i.license}.items()
            if v is not None
        }
        for i in db.scalars(select(Indicator)).all()
    ]
    text = build_pack(current + 1, indicators, body.yara, body.config)
    try:
        signature = sign(text)
        key = public_key_b64()
    except SigningUnavailable as e:
        raise HTTPException(503, str(e)) from e
    db.add(RulePackVersion(version=current + 1, body=text, signature=signature, created_by=admin.id))
    audit(db, admin.id, "rules.publish", f"v{current + 1}, {len(indicators)} indicators")
    db.commit()
    return {"version": current + 1, "indicators": len(indicators), "public_key": key}
