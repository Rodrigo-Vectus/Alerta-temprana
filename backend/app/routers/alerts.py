from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select

from app.db import SessionLocal
from app.models import Alert, CveEnrichment, KevVulnerability
from app.scoring import rescore_all

router = APIRouter(prefix="/api/alerts", tags=["alertas"])


def _alert(a, k, e, full=False):
    d = {"code": a.code, "cve_id": a.cve_id, "score": a.score, "level": a.level, "status": a.status,
         "vendor": k.vendor_project, "product": k.product, "name": k.vulnerability_name,
         "date_added": k.date_added, "due_date": k.due_date,
         "cvss": e.cvss_score if e else None, "epss": e.epss if e else None,
         "clients": sorted({m["client"] for m in (a.matched_clients or [])}),
         "created_at": a.created_at, "updated_at": a.updated_at}
    if full:
        d.update(description=k.short_description, required_action=k.required_action, notes=k.notes,
                 ransomware=k.known_ransomware,
                 cwes=sorted(set(k.cwes or []) | set((e.cwes if e else None) or [])),
                 cvss_vector=e.cvss_vector if e else None, cvss_version=e.cvss_version if e else None,
                 epss_percentile=e.epss_percentile if e else None, nvd_ok=e.nvd_ok if e else False,
                 references=(e.ref_urls if e else []) or [],
                 breakdown=a.breakdown, matched_clients=a.matched_clients, history=a.history)
    return d


def _base_query():
    return (select(Alert, KevVulnerability, CveEnrichment)
            .join(KevVulnerability, KevVulnerability.cve_id == Alert.cve_id)
            .join(CveEnrichment, CveEnrichment.cve_id == Alert.cve_id, isouter=True))


@router.get("")
def list_alerts(status: str | None = None, min_score: int = 0, limit: int = Query(50, le=500)):
    with SessionLocal() as db:
        q = _base_query().where(Alert.score >= min_score).order_by(Alert.score.desc(), Alert.id.desc()).limit(limit)
        if status:
            q = q.where(Alert.status == status)
        return [_alert(a, k, e) for a, k, e in db.execute(q).all()]


@router.post("/rescore-all")
def rescore():
    return rescore_all()


@router.get("/{code}")
def get_alert(code: str):
    with SessionLocal() as db:
        row = db.execute(_base_query().where(Alert.code == code.upper())).first()
        if not row:
            raise HTTPException(404, "Alerta no encontrada")
        return _alert(*row, full=True)
