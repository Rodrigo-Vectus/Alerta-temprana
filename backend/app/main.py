from contextlib import asynccontextmanager

from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
from sqlalchemy import func, select, text

from app.db import SessionLocal, engine, init_db
from app.models import CollectorRun, KevEvent, KevVulnerability


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Vectus SAT - Alerta Temprana", version="0.2.0",
              docs_url="/api/docs", openapi_url="/api/openapi.json", lifespan=lifespan)


def _vuln(v: KevVulnerability):
    return {
        "cve_id": v.cve_id, "vendor": v.vendor_project, "product": v.product,
        "name": v.vulnerability_name, "description": v.short_description,
        "ransomware": v.known_ransomware, "cwes": v.cwes,
        "date_added": v.date_added, "due_date": v.due_date,
        "required_action": v.required_action, "change_count": v.change_count,
    }


@app.get("/api/health")
def health():
    try:
        with engine.connect() as conn:
            version = conn.execute(text("select version()")).scalar()
        return {"status": "ok", "db": "ok", "postgres": version.split(",")[0]}
    except Exception as exc:
        return JSONResponse(status_code=503, content={"status": "degraded", "db": str(exc)})


@app.get("/api/kev/stats")
def kev_stats():
    with SessionLocal() as db:
        last = db.scalar(select(CollectorRun).order_by(CollectorRun.id.desc()).limit(1))
        return {
            "total_kev": db.scalar(select(func.count()).select_from(KevVulnerability)),
            "ransomware_known": db.scalar(select(func.count()).where(KevVulnerability.known_ransomware == "Known")),
            "pending_events": db.scalar(select(func.count()).where(KevEvent.processed.is_(False))),
            "last_run": None if not last else {
                "status": last.status, "catalog_version": last.catalog_version,
                "started_at": last.started_at, "new": last.new_count,
                "updated": last.updated_count, "error": last.error,
            },
        }


@app.get("/api/kev/recent")
def kev_recent(limit: int = Query(20, le=200)):
    with SessionLocal() as db:
        rows = db.scalars(select(KevVulnerability)
                          .order_by(KevVulnerability.date_added.desc(), KevVulnerability.cve_id.desc())
                          .limit(limit)).all()
        return [_vuln(v) for v in rows]


@app.get("/api/kev/events")
def kev_events(limit: int = Query(50, le=500), pending_only: bool = False):
    with SessionLocal() as db:
        q = select(KevEvent).order_by(KevEvent.id.desc()).limit(limit)
        if pending_only:
            q = q.where(KevEvent.processed.is_(False))
        return [{"id": e.id, "cve_id": e.cve_id, "type": e.event_type, "changed": e.changed_fields,
                 "processed": e.processed, "created_at": e.created_at} for e in db.scalars(q).all()]


@app.get("/api/collector/runs")
def collector_runs(limit: int = Query(10, le=100)):
    with SessionLocal() as db:
        rows = db.scalars(select(CollectorRun).order_by(CollectorRun.id.desc()).limit(limit)).all()
        return [{"id": r.id, "status": r.status, "version": r.catalog_version, "total": r.total,
                 "new": r.new_count, "updated": r.updated_count, "error": r.error,
                 "started_at": r.started_at, "finished_at": r.finished_at} for r in rows]


from app.routers import alerts as alerts_router, clients as clients_router  # noqa: E402

app.include_router(alerts_router.router)
app.include_router(clients_router.router)
