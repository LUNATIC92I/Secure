import base64
import json
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .config import get_settings


class SigningUnavailable(Exception):
    pass


def _key() -> Ed25519PrivateKey:
    seed = get_settings().rules_signing_seed
    if not seed:
        raise SigningUnavailable("SENTINEL_RULES_SIGNING_SEED is not configured")
    raw = base64.b64decode(seed)
    if len(raw) != 32:
        raise SigningUnavailable("signing seed must be 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)


def public_key_b64() -> str:
    return base64.b64encode(_key().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def build_pack(version: int, indicators: list[dict], yara: str, config: dict) -> str:
    """Serialises a rule pack in the exact schema the mobile app validates."""
    return json.dumps(
        {
            "schema": 1,
            "version": version,
            "issuedAt": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "source": "Sentinel backend",
            "config": config,
            "indicators": indicators,
            "yara": yara,
        },
        ensure_ascii=False,
        indent=1,
    )


def sign(body: str) -> str:
    return base64.b64encode(_key().sign(body.encode())).decode()
