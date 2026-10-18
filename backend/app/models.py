from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def now() -> datetime:
    return datetime.now(UTC)


class Device(Base):
    """A registered app installation. Only the SHA-256 of its bearer token is stored."""

    __tablename__ = "devices"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    role: Mapped[str] = mapped_column(String(16), default="device")  # device | analyst | admin
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Indicator(Base):
    __tablename__ = "indicators"
    __table_args__ = (UniqueConstraint("type", "value"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    type: Mapped[str] = mapped_column(String(16), index=True)  # package|cert_sha256|file_sha256|domain|url_prefix
    value: Mapped[str] = mapped_column(String(512), index=True)
    # sha256(lower(domain)) so devices can query without revealing the domain.
    value_sha256: Mapped[str] = mapped_column(String(64), index=True)
    family: Mapped[str] = mapped_column(String(128), default="unknown")
    category: Mapped[str] = mapped_column(String(32), default="malware")
    source: Mapped[str] = mapped_column(String(128))
    license: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class RulePackVersion(Base):
    __tablename__ = "rule_packs"
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    body: Mapped[str] = mapped_column(Text)
    signature: Mapped[str] = mapped_column(String(128))
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ProviderConfig(Base):
    __tablename__ = "providers"
    name: Mapped[str] = mapped_column(String(32), primary_key=True)
    enabled: Mapped[bool] = mapped_column(default=False)
    last_success: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(256), nullable=True)


class SyncedIncident(Base):
    """Opt-in incident backup. Always scoped to its device (no cross-device access)."""

    __tablename__ = "incidents"
    __table_args__ = (UniqueConstraint("device_id", "incident_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    incident_id: Mapped[str] = mapped_column(String(64))
    data: Mapped[dict] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    actor: Mapped[str] = mapped_column(String(36))
    action: Mapped[str] = mapped_column(String(64))
    detail: Mapped[str] = mapped_column(String(512), default="")
