import hashlib
import hmac
import secrets

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import get_db
from .models import AuditLog, Device

ROLES = {"device": 0, "analyst": 1, "admin": 2}


def new_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def current_device(request: Request, db: Session = Depends(get_db)) -> Device:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
    digest = hash_token(auth[7:].strip())
    device = db.scalar(select(Device).where(Device.token_hash == digest))
    # Constant-time comparison on the looked-up hash defends against timing probes.
    if device is None or not hmac.compare_digest(device.token_hash, digest):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token", headers={"WWW-Authenticate": "Bearer"})
    request.state.principal = device.id
    return device


def require_role(role: str):
    def dep(device: Device = Depends(current_device)) -> Device:
        if ROLES.get(device.role, -1) < ROLES[role]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")
        return device

    return dep


def audit(db: Session, actor: str, action: str, detail: str = "") -> None:
    db.add(AuditLog(actor=actor, action=action, detail=detail[:512]))
