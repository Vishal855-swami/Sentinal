from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db, init_db
from app.models import ScanRun
from app.scan_worker import run_scan, scanner
from app.schemas import ScanCreate, ScanDetail, ScanSummary

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


@app.get("/health")
def health():
    return {"status": "ok", "nmap_available": scanner.is_available()}


@app.post("/api/scans", response_model=ScanSummary, status_code=status.HTTP_202_ACCEPTED)
def create_scan(
    request: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    scan = ScanRun(target=request.target, status="queued", message="Waiting for the scanner.")
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


@app.get("/reports/{scan_id}", response_class=HTMLResponse, include_in_schema=False)
def scan_report(scan_id: str, request: Request, db: Session = Depends(get_db)):
    scan = db.scalar(select(ScanRun).where(ScanRun.id == scan_id))
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return templates.TemplateResponse(request=request, name="report.html", context={"scan": scan})