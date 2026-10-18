import base64
import hashlib
import json
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .conftest import register


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/health").headers["X-Content-Type-Options"] == "nosniff"


def test_auth_required_everywhere(client):
    for method, path in [("post", "/v1/reputation"), ("get", "/v1/rules/latest"), ("get", "/v1/incidents"), ("delete", "/v1/me"), ("get", "/v1/admin/audit")]:
        assert getattr(client, method)(path).status_code == 401
    assert client.get("/v1/incidents", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_rbac(client):
    dev, _ = register(client)
    assert client.get("/v1/admin/audit", headers=dev).status_code == 403
    assert client.post("/v1/admin/rules/publish", headers=dev, json={}).status_code == 403
    assert client.post("/v1/devices/register", json={"bootstrap_token": "wrong"}).status_code == 403
    admin, info = register(client, admin=True)
    assert info["role"] == "admin"
    assert client.get("/v1/admin/audit", headers=admin).status_code == 200


def test_token_stored_hashed(client):
    from app.db import get_db
    from app.models import Device

    _, info = register(client)
    db = next(get_db())
    d = db.get(Device, info["device_id"])
    assert d.token_hash == hashlib.sha256(info["token"].encode()).hexdigest()
    assert info["token"] not in d.token_hash


def test_reputation_local_and_hashed_domain(client):
    admin, _ = register(client, admin=True)
    r = client.post("/v1/admin/indicators", headers=admin, json=[
        {"type": "domain", "value": "Evil.Example", "family": "Phish", "category": "phishing", "source": "test"},
        {"type": "file_sha256", "value": "a" * 64, "family": "Trojan", "source": "test"},
    ])
    assert r.json() == {"added": 2}
    dev, _ = register(client)
    h = hashlib.sha256(b"evil.example").hexdigest()
    assert client.post("/v1/reputation", headers=dev, json={"type": "domain_sha256", "value": h}).json()["verdict"] == "malicious"
    assert client.post("/v1/reputation", headers=dev, json={"type": "url", "value": "https://login.evil.example/x"}).json()["verdict"] == "malicious"
    assert client.post("/v1/reputation", headers=dev, json={"type": "file_sha256", "value": "a" * 64}).json()["verdict"] == "malicious"
    assert client.post("/v1/reputation", headers=dev, json={"type": "file_sha256", "value": "b" * 64}).json()["verdict"] == "unknown"


def test_input_validation_does_not_echo_values(client):
    dev, _ = register(client)
    r = client.post("/v1/reputation", headers=dev, json={"type": "url", "value": "javascript:secret-token"})
    assert r.status_code == 422
    assert "secret-token" not in r.text
    assert client.post("/v1/reputation", headers=dev, json={"type": "file_sha256", "value": "zz"}).status_code == 422


def test_rate_limit(client, monkeypatch):
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "rate_limit_per_minute", 2)
    dev, _ = register(client)
    codes = [client.post("/v1/reputation", headers=dev, json={"type": "file_sha256", "value": "c" * 64}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_signed_rule_pack_round_trip(client):
    admin, _ = register(client, admin=True)
    ind = {"type": "package", "value": "com.bad.app", "family": "X", "category": "stalkerware", "source": "test"}
    client.post("/v1/admin/indicators", headers=admin, json=[ind])
    pub = client.post("/v1/admin/rules/publish", headers=admin, json={"yara": "", "config": {"iosLatestMajor": 26}})
    assert pub.status_code == 201
    dev, _ = register(client)
    pack = client.get("/v1/rules/latest", headers=dev).json()
    body = json.loads(pack["body"])
    assert body["schema"] == 1 and body["version"] == 1
    assert body["indicators"][0]["value"] == "com.bad.app"
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub.json()["public_key"]))
    key.verify(base64.b64decode(pack["signature"]), pack["body"].encode())  # raises if invalid
    assert client.post("/v1/admin/rules/publish", headers=admin, json={}).json()["version"] == 2


def test_incident_sync_is_scoped_to_device(client):
    a, _ = register(client)
    b, _ = register(client)
    assert client.put("/v1/incidents", headers=a, json={"incident_id": "INC-ABC", "data": {"severity": "high"}}).status_code == 204
    assert len(client.get("/v1/incidents", headers=a).json()) == 1
    assert client.get("/v1/incidents", headers=b).json() == []
    client.delete("/v1/incidents/INC-ABC", headers=b)  # other device cannot delete it
    assert len(client.get("/v1/incidents", headers=a).json()) == 1
    assert client.put("/v1/incidents", headers=a, json={"incident_id": "../etc", "data": {}}).status_code == 422


def test_delete_me_erases_data(client):
    a, _ = register(client)
    client.put("/v1/incidents", headers=a, json={"incident_id": "INC-1", "data": {}})
    assert client.delete("/v1/me", headers=a).status_code == 204
    assert client.get("/v1/incidents", headers=a).status_code == 401


def test_body_size_limit(client):
    dev, _ = register(client)
    r = client.put("/v1/incidents", headers={**dev, "content-type": "application/json"}, content=b"{" + b" " * 300_000 + b"}")
    assert r.status_code == 413


def test_provider_toggle_and_audit(client):
    admin, _ = register(client, admin=True)
    assert client.put("/v1/admin/providers/virustotal?enabled=true", headers=admin).json()["enabled"] is True
    assert client.put("/v1/admin/providers/unknown?enabled=true", headers=admin).status_code == 404
    actions = [e["action"] for e in client.get("/v1/admin/audit", headers=admin).json()]
    assert "provider.toggle" in actions


def test_feed_parsers():
    from app.feeds import parse_stalkerware, parse_urlhaus

    csv_text = '# comment\n"1","2024-01-01","http://bad.example/payload.exe","online","2024","malware_download","x","y","z"\n'
    assert parse_urlhaus(csv_text)[0]["value"] == "bad.example/payload.exe"
    y = "- name: TestWare\n  packages: [com.test.ware]\n  websites: [testware.example]\n  c2:\n    domains: [c2.testware.example]\n"
    types = sorted(i["type"] for i in parse_stalkerware(y))
    assert types == ["domain", "domain", "package"]


def test_alembic_migration(tmp_path):
    url = f"sqlite:///{tmp_path}/m.db"
    r = subprocess.run([sys.executable, "-m", "alembic", "-x", "unused=1", "-c", "alembic.ini", "upgrade", "head"],
                       capture_output=True, text=True, env={"SENTINEL_DATABASE_URL": url, "PATH": ""})
    assert r.returncode == 0, r.stderr
