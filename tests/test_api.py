import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import database, scan_worker
from app.main import app
from app.scanner import ScanOutcome


@pytest.fixture
def client(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    test_sessions = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    monkeypatch.setattr(database, "engine", engine)
    monkeypatch.setattr(database, "SessionLocal", test_sessions)

    class FakeScanner:
        def scan(self, target):
            return ScanOutcome(
                hosts=[
                    {
                        "ip_address": "192.168.1.20",
                        "hostname": "camera-lab",
                        "device_type": "Probable CCTV/DVR",
                        "probable_cctv_dvr": True,
                        "identification_evidence": ["TCP port 554 is commonly associated with video devices"],
                        "services": [
                            {"protocol": "tcp", "port": 554, "name": "rtsp", "product": "", "version": ""}
                        ],
                    }
                ]
            )

    monkeypatch.setattr(scan_worker, "scanner", FakeScanner())
    with TestClient(app) as test_client:
        yield test_client
    engine.dispose()


def test_scan_validation_rejects_unapproved_or_public_targets(client):
    unauthorized = client.post("/api/scans", json={"target": "192.168.1.0/24", "authorized": False})
    public = client.post("/api/scans", json={"target": "8.8.8.8", "authorized": True})

    assert unauthorized.status_code == 422
    assert public.status_code == 422


def test_scan_lifecycle_persists_results_and_printable_report(client):
    response = client.post("/api/scans", json={"target": "192.168.1.0/24", "authorized": True})

    assert response.status_code == 202
    scan_id = response.json()["id"]
    detail = client.get(f"/api/scans/{scan_id}")
    assert detail.status_code == 200
    assert detail.json()["status"] == "completed"
    assert detail.json()["device_count"] == 1
    assert detail.json()["findings"][0]["title"] == "Exposed service: rtsp on 554/tcp"

    report = client.get(f"/reports/{scan_id}")
    assert report.status_code == 200
    assert "camera-lab" in report.text
    assert "Print / Save PDF" in report.text


def test_large_private_network_is_rejected(client):
    response = client.post("/api/scans", json={"target": "10.0.0.0/16", "authorized": True})

    assert response.status_code == 422