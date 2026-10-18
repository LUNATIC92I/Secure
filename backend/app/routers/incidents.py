from fastapi import APIRouter, Depends
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Device, SyncedIncident
from ..schemas import IncidentIn
from ..security import current_device

router = APIRouter(prefix="/v1/incidents", tags=["incidents"])


# Every query filters on the authenticated device id: an incident id from another device
# simply does not exist for the caller (no IDOR).
@router.get("")
def list_incidents(db: Session = Depends(get_db), device: Device = Depends(current_device)):
    rows = db.scalars(select(SyncedIncident).where(SyncedIncident.device_id == device.id)).all()
    return [{"incident_id": r.incident_id, "data": r.data, "updated_at": r.updated_at.isoformat()} for r in rows]


@router.put("", status_code=204)
def upsert(body: IncidentIn, db: Session = Depends(get_db), device: Device = Depends(current_device)):
    row = db.scalar(select(SyncedIncident).where(SyncedIncident.device_id == device.id, SyncedIncident.incident_id == body.incident_id))
    if row is None:
        db.add(SyncedIncident(device_id=device.id, incident_id=body.incident_id, data=body.data))
    else:
        row.data = body.data
    db.commit()


@router.delete("/{incident_id}", status_code=204)
def remove(incident_id: str, db: Session = Depends(get_db), device: Device = Depends(current_device)):
    db.execute(delete(SyncedIncident).where(SyncedIncident.device_id == device.id, SyncedIncident.incident_id == incident_id))
    db.commit()
