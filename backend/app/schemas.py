from typing import Literal

from pydantic import BaseModel, Field, field_validator


class RegisterIn(BaseModel):
    bootstrap_token: str | None = Field(default=None, max_length=256)


class RegisterOut(BaseModel):
    device_id: str
    token: str
    role: str


class ReputationIn(BaseModel):
    type: Literal["file_sha256", "domain_sha256", "url"]
    value: str = Field(min_length=1, max_length=2048)

    @field_validator("value")
    @classmethod
    def check(cls, v: str, info):
        t = info.data.get("type")
        if t in ("file_sha256", "domain_sha256"):
            v = v.lower()
            if len(v) != 64 or any(c not in "0123456789abcdef" for c in v):
                raise ValueError("must be a lowercase hex SHA-256")
        elif not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("only http(s) URLs")
        return v


class ReputationOut(BaseModel):
    verdict: Literal["malicious", "suspicious", "clean", "unknown", "error"]
    provider: str
    detail: str | None = None
    sources: list[dict] = []


class IncidentIn(BaseModel):
    incident_id: str = Field(pattern=r"^INC-[A-Za-z0-9-]{1,60}$")
    data: dict

    @field_validator("data")
    @classmethod
    def size(cls, v: dict):
        import json

        if len(json.dumps(v)) > 64 * 1024:
            raise ValueError("incident too large")
        return v


class IndicatorIn(BaseModel):
    type: Literal["package", "cert_sha256", "file_sha256", "domain", "url_prefix"]
    value: str = Field(min_length=1, max_length=512)
    family: str = Field(default="unknown", max_length=128)
    category: Literal["malware", "stalkerware", "phishing", "adware", "pua", "test"] = "malware"
    source: str = Field(max_length=128)
    license: str | None = Field(default=None, max_length=64)


class PublishIn(BaseModel):
    yara: str = Field(default="", max_length=256 * 1024)
    config: dict = {}


class RoleIn(BaseModel):
    role: Literal["device", "analyst", "admin"]
