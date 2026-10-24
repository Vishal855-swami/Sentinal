import csv
import hashlib
import io
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db, init_db
from app.models import ScanRun, User
from app.scan_worker import request_cancel, run_scan, scanner
from app.schemas import (
    AuthToken,
    ScanCreate,
    ScanDetail,
    ScanDetail,
    ScanSummary,
    UserLogin,
    UserRead,
    UserRegister,
)

ROOT = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(ROOT / "templates"))


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Sentinal CCTV/DVR Assessment",
    description="Authorized, bounded, non-destructive network service assessment.",
    version="0.1.0",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16).encode()
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return salt.decode() + ":" + digest.hex()


def _verify_password(password: str, password_hash: str) -> bool:
    try:
        salt, digest = password_hash.split(":", 1)
    except ValueError:
        return False
    expected = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return secrets.compare_digest(expected.hex(), digest)


def get_authenticated_user(db: Session, authorization: str | None) -> User | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="A valid bearer token is required.")
    user = db.scalar(select(User).where(User.api_token == token))
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")
    return user


@app.get("/health")
def health():
    return {"status": "ok", "nmap_available": scanner.is_available()}


@app.post("/api/users/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register_user(payload: UserRegister, db: Session = Depends(get_db)):
    existing = db.scalar(select(User).where(User.username == payload.username))
    if existing is not None:
        raise HTTPException(status_code=409, detail="Username is already in use.")

    user = User(username=payload.username, password_hash=_hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/api/users/login", response_model=AuthToken)
def login_user(payload: UserLogin, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == payload.username))
    if user is None or not _verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    token = secrets.token_urlsafe(32)
    user.api_token = token
    db.commit()
    return {"access_token": token, "token_type": "bearer"}


@app.post("/api/scans", response_model=ScanSummary, status_code=status.HTTP_202_ACCEPTED)
def create_scan(
    request: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None),
):
    current_user = get_authenticated_user(db, authorization)
    scan = ScanRun(
        target=request.target,
        status="queued",
        message="Waiting for the scanner.",
        user_id=current_user.id if current_user is not None else None,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(run_scan, scan.id)
    return scan


@app.get("/api/scans", response_model=list[ScanSummary])
def list_scans(db: Session = Depends(get_db)):
    return db.scalars(select(ScanRun).order_by(ScanRun.created_at.desc()).limit(50)).all()


@app.get("/api/scans/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.scalar(select(ScanRun).where(ScanRun.id == scan_id))
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


@app.post("/api/scans/{scan_id}/cancel", response_model=ScanDetail)
def cancel_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.scalar(select(ScanRun).where(ScanRun.id == scan_id))
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")

    request_cancel(scan_id)
    scan.status = "cancelled"
    scan.message = "Scan cancelled by user."
    scan.completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(scan)
    return scan


@app.get("/reports/{scan_id}", response_class=HTMLResponse, include_in_schema=False)
def scan_report(scan_id: str, request: Request, db: Session = Depends(get_db)):
    scan = db.scalar(select(ScanRun).where(ScanRun.id == scan_id))
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return templates.TemplateResponse(request=request, name="report.html", context={"scan": scan})


def _csv_cell(value: object) -> str:
    text = "" if value is None else str(value)
    if text.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text


@app.get("/reports/{scan_id}/export")
def export_scan_report(scan_id: str, format: str = "json", db: Session = Depends(get_db)):
    scan = db.scalar(select(ScanRun).where(ScanRun.id == scan_id))
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if format not in {"json", "csv"}:
        raise HTTPException(status_code=422, detail="Export format must be json or csv.")

    filename = f"sentinal-report-{scan.id}.{format}"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    if format == "json":
        report = ScanDetail.model_validate(scan).model_dump(mode="json")
        return JSONResponse(content=report, headers=headers)

    columns = [
        "scan_id", "target", "status", "created_at", "completed_at", "record_type",
        "ip_address", "hostname", "device_type", "probable_cctv_dvr", "identification_evidence",
        "protocol", "port", "service", "product", "version", "severity", "title",
        "details", "evidence", "recommendation", "confidence",
    ]
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=columns)
    writer.writeheader()

    def write_row(values: dict) -> None:
        writer.writerow({key: _csv_cell(value) for key, value in values.items()})

    common = {
        "scan_id": scan.id,
        "target": scan.target,
        "status": scan.status,
        "created_at": scan.created_at.isoformat() if scan.created_at else "",
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else "",
    }
    for device in scan.devices:
        device_data = {
            "ip_address": device.ip_address,
            "hostname": device.hostname or "",
            "device_type": device.device_type,
            "probable_cctv_dvr": device.probable_cctv_dvr,
            "identification_evidence": "; ".join(device.identification_evidence or []),
        }
        for service in device.services or [None]:
            write_row({
                **common, **device_data, "record_type": "service" if service else "device",
                "protocol": service.get("protocol", ""), "port": service.get("port", ""),
                "service": service.get("name", ""), "product": service.get("product", ""),
                "version": service.get("version", ""),
            } if service else {
                **common, **device_data, "record_type": "device",
            })
    for finding in scan.findings:
        write_row({
            **common, "record_type": "finding", "ip_address": finding.device_ip,
            "severity": finding.severity, "title": finding.title, "details": finding.details,
            "evidence": finding.evidence, "recommendation": finding.recommendation,
            "confidence": finding.confidence,
        })
    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers=headers,
    )