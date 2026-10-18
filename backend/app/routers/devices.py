import hmac
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import delete
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import Device, SyncedIncident
from ..ratelimit import limiter
from ..schemas import RegisterIn, RegisterOut
from ..security import audit, current_device, hash_token, new_token

router = APIRouter(prefix="/v1", tags=["devices"])


@router.post("/devices/register", response_model=RegisterOut, status_code=201)
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)):
    """Creates an anonymous device identity. The token is returned once and stored hashed."""
    ip = request.client.host if request.client else "unknown"
    if not limiter.allow(f"register:{ip}", get_settings().register_limit_per_hour, 3600):
        raise HTTPException(429, "too many registrations")
    role = "device"
    boot = get_settings().admin_bootstrap_token
    if body.bootstrap_token:
        if not boot or not hmac.compare_digest(body.bootstrap_token, boot):
            raise HTTPException(403, "invalid bootstrap token")
        role = "admin"
    token = new_token()
    device = Device(id=str(uuid.uuid4()), token_hash=hash_token(token), role=role)
    db.add(device)
    audit(db, device.id, "device.register", role)
    db.commit()
    return RegisterOut(device_id=device.id, token=token, role=role)


@router.delete("/me", status_code=204)
def delete_me(db: Session = Depends(get_db), device: Device = Depends(current_device)):
    """Erases every record tied to the calling device (GDPR erasure)."""
    db.execute(delete(SyncedIncident).where(SyncedIncident.device_id == device.id))
    audit(db, device.id, "device.delete")
    db.delete(device)
    db.commit()
