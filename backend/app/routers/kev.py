from fastapi import APIRouter, Query
from sqlalchemy import func, select

from app.db import SessionLocal
from app.models import CollectorRun, KevEvent, KevVulnerability

router = APIRouter(prefix="/api", tags=["kev"])


def _vuln(v: KevVulnerability):
    return {"cve_id": v.cve_id, "vendor": v.vendor_project, "product": v.product,
            "name": v.vulnerability_name, "description": v.short_description,
            "ransomware": v.known_ransomware, "cwes": v.cwes, "date_added": v.date_added,
            "due_date": v.due_date, "required_action": v.required_action, "change_count": v.change_count}


@router.get("/kev/stats")
def kev_stats():
    with SessionLocal() as db:
        last = db.scalar(select(CollectorRun).order_by(CollectorRun.id.desc()).limit(1))
        return {
            "total_kev": db.scalar(select(func.count()).select_from(KevVulnerability)),
            "ransomware_known": db.scalar(select(func.count()).where(KevVulnerability.known_ransomware == "Known")),
            "pending_events": db.scalar(select(func.count()).where(KevEvent.processed.is_(False))),
            "last_run": None if not last else {
                "status": last.status, "catalog_version": last.catalog_version, "started_at": last.started_at,
                "new": last.new_count, "updated": last.updated_count, "error": last.error},
        }


@router.get("/kev/recent")
def kev_recent(limit: int = Query(20, le=200)):
    with SessionLocal() as db:
        rows = db.scalars(select(KevVulnerability).order_by(KevVulnerability.date_added.desc(),
                                                            KevVulnerability.cve_id.desc()).limit(limit)).all()
        return [_vuln(v) for v in rows]


@router.get("/kev/events")
def kev_events(limit: int = Query(50, le=500), pending_only: bool = False):
    with SessionLocal() as db:
        q = select(KevEvent).order_by(KevEvent.id.desc()).limit(limit)
        if pending_only:
            q = q.where(KevEvent.processed.is_(False))
        return [{"id": e.id, "cve_id": e.cve_id, "type": e.event_type, "changed": e.changed_fields,
                 "processed": e.processed, "created_at": e.created_at} for e in db.scalars(q).all()]


@router.get("/collector/runs")
def collector_runs(limit: int = Query(10, le=100)):
    with SessionLocal() as db:
        rows = db.scalars(select(CollectorRun).order_by(CollectorRun.id.desc()).limit(limit)).all()
        return [{"id": r.id, "status": r.status, "version": r.catalog_version, "total": r.total,
                 "new": r.new_count, "updated": r.updated_count, "error": r.error,
                 "started_at": r.started_at, "finished_at": r.finished_at} for r in rows]
