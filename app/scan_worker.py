import logging
from datetime import datetime, timezone

from sqlalchemy import select

from app import database
from app.models import Device, Finding, ScanRun
from app.scanner import NmapScanner, ScannerError

logger = logging.getLogger(__name__)
scanner = NmapScanner()
_cancelled_scans: set[str] = set()


def _service_finding(ip_address: str, service: dict) -> Finding:
    port = service["port"]
    name = service["name"] or "unknown service"
    details = f"TCP port {port} is open; Nmap identified the service as {name}."
    severity = "info"
    recommendation = "Confirm this service is required and restrict access to trusted networks."

    if port == 23 or name == "telnet":
        severity = "high"
        recommendation = "Disable Telnet and use an encrypted management service restricted to trusted networks."
    elif port == 21 or name == "ftp":
        severity = "low"
        recommendation = "Disable FTP if it is not required; otherwise use an encrypted alternative and restrict access."
    elif port in (80, 8080) and name in ("http", "http-proxy"):
        severity = "low"
        recommendation = "Prefer HTTPS for management and restrict the interface to trusted networks."

    evidence = f"Observed open {service['protocol']}/{port}; service={name}; product={service['product']}; version={service['version']}"
    return Finding(
        device_ip=ip_address,
        severity=severity,
        title=f"Exposed service: {name} on {port}/{service['protocol']}",
        details=details,
        evidence=evidence,
        recommendation=recommendation,
        confidence="high",
    )


def is_cancelled(scan_id: str) -> bool:
    return scan_id in _cancelled_scans


def request_cancel(scan_id: str) -> None:
    _cancelled_scans.add(scan_id)
    db = database.SessionLocal()
    try:
        scan = db.scalar(select(ScanRun).where(ScanRun.id == scan_id))
        if scan is not None and scan.status in {"queued", "running"}:
            scan.status = "cancelled"
            scan.message = "Scan cancelled by user."
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()


def run_scan(scan_id: str) -> None:
    db = database.SessionLocal()
    try:
        scan = db.scalar(select(ScanRun).where(ScanRun.id == scan_id))
        if scan is None or scan.status not in {"queued", "running"}:
            return
        if is_cancelled(scan_id):
            scan.status = "cancelled"
            scan.message = "Scan cancelled by user."
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
            return

        scan.status = "running"
        scan.message = "Nmap is checking the authorized target."
        db.commit()

        outcome = scanner.scan(scan.target)
        if is_cancelled(scan_id):
            scan.status = "cancelled"
            scan.message = "Scan cancelled by user."
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
            return

        for host in outcome.hosts:
            if is_cancelled(scan_id):
                scan.status = "cancelled"
                scan.message = "Scan cancelled by user."
                scan.completed_at = datetime.now(timezone.utc)
                db.commit()
                return
            device = Device(
                ip_address=host["ip_address"],
                hostname=host["hostname"],
                device_type=host["device_type"],
                probable_cctv_dvr=host["probable_cctv_dvr"],
                identification_evidence=host["identification_evidence"],
                services=host["services"],
            )
            scan.devices.append(device)
            scan.findings.extend(_service_finding(host["ip_address"], service) for service in host["services"])

        scan.status = "completed"
        scan.message = "Scan completed. Open services are observations, not confirmed vulnerabilities."
        scan.completed_at = datetime.now(timezone.utc)
        scan.host_count = len(outcome.hosts)
        scan.device_count = sum(host["probable_cctv_dvr"] for host in outcome.hosts)
        scan.finding_count = sum(len(host["services"]) for host in outcome.hosts)
        db.commit()
    except ScannerError as exc:
        db.rollback()
        scan = db.scalar(select(ScanRun).where(ScanRun.id == scan_id))
        if scan is not None:
            scan.status = "failed"
            scan.message = str(exc)
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
    except Exception:
        logger.exception("Unexpected error while processing scan %s", scan_id)
        db.rollback()
        scan = db.scalar(select(ScanRun).where(ScanRun.id == scan_id))
        if scan is not None:
            scan.status = "failed"
            scan.message = "An unexpected error occurred while processing this scan."
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()