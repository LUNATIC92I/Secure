import base64
import os

import pytest
from fastapi.testclient import TestClient

# Test-only signing seed (32 zero-derived bytes); never used outside tests.
os.environ["SENTINEL_RULES_SIGNING_SEED"] = base64.b64encode(bytes(range(32))).decode()
os.environ["SENTINEL_ADMIN_BOOTSTRAP_TOKEN"] = "bootstrap-test"  # noqa: S105 - test fixture


@pytest.fixture
def client(tmp_path):
    from app import db
    from app.config import get_settings
    from app.db import Base
    from app.main import app
    from app.ratelimit import limiter

    get_settings.cache_clear()
    engine = db.init_engine(f"sqlite:///{tmp_path}/t.db")
    from app import models  # noqa: F401

    Base.metadata.create_all(engine)
    limiter.reset()
    with TestClient(app) as c:
        yield c


def register(client, admin=False):
    r = client.post("/v1/devices/register", json={"bootstrap_token": "bootstrap-test"} if admin else {})
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}, r.json()
