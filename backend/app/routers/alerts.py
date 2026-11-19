from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select

from app.auth import get_current_user
from app.db import SessionLocal
from app.models import Alert, CollectorRun, Communication, CveEnrichment, KevVulnerability, User
from app.scoring import rescore_all

router = APIRouter(prefix="/api/alerts", tags=["alertas"])

# Estados automáticos (los asigna el motor) y manuales (los asigna el analista)
STATUSES = {
    "candidata": "Candidata",
    "monitoreo": "Monitoreo",
    "descartada_auto": "Sin aviso (puntaje bajo)",
    "en_revision": "En revisión",
    "aprobada": "Aprobada",
    "enviada": "Enviada",
    "descartada": "Descartada",
    "no_enviada": "No enviada",
    "cerrada": "Cerrada",
}
MANUAL_TARGETS = {"candidata", "monitoreo", "en_revision", "descartada", "cerrada"}

# Pestañas de la pantalla Alertas
NEW_DAYS = 7
SENT = ("enviada", "cerrada")
NOT_SENT = ("no_enviada", "descartada")


class StatusIn(BaseModel):
    status: str
    comment: str = ""


def _alert(a, k, e, full=False):
    d = {"code": a.code, "cve_id": a.cve_id, "score": a.score, "level": a.level, "status": a.status,
         "vendor": k.vendor_project, "product": k.product, "name": k.vulnerability_name,
         "ransomware": k.known_ransomware,
         "date_added": k.date_added, "due_date": k.due_date,
         "cvss": e.cvss_score if e else None, "epss": e.epss if e else None,
         "clients": sorted({m["client"] for m in (a.matched_clients or [])}),
         "origin": (a.history or [{}])[0].get("evento"),
         "created_at": a.created_at, "updated_at": a.updated_at}
    if full:
        d.update(description=k.short_description, required_action=k.required_action, notes=k.notes,
                 cwes=sorted(set(k.cwes or []) | set((e.cwes if e else None) or [])),
                 cvss_vector=e.cvss_vector if e else None, cvss_version=e.cvss_version if e else None,
                 cvss_severity=e.cvss_severity if e else None,
                 epss_percentile=e.epss_percentile if e else None, nvd_ok=e.nvd_ok if e else False,
                 nvd_published=e.nvd_published if e else None,
                 references=(e.ref_urls if e else []) or [],
                 breakdown=a.breakdown, matched_clients=a.matched_clients, history=a.history)
    return d


def _base_query():
    return (select(Alert, KevVulnerability, CveEnrichment)
            .join(KevVulnerability, KevVulnerability.cve_id == Alert.cve_id)
            .join(CveEnrichment, CveEnrichment.cve_id == Alert.cve_id, isouter=True))


@router.get("")
def list_alerts(status: str | None = None, min_score: int = 0, q: str | None = None,
                new_days: int | None = None, order: str = "score", limit: int = Query(100, le=1000)):
    with SessionLocal() as db:
        query = _base_query().where(Alert.score >= min_score)
        if status:
            query = query.where(Alert.status.in_(status.split(",")))
        if new_days:
            query = query.where(Alert.created_at >= datetime.now(timezone.utc) - timedelta(days=new_days))
        if q:
            like = f"%{q.strip()}%"
            query = query.where(Alert.cve_id.ilike(like) | Alert.code.ilike(like)
                                | KevVulnerability.vendor_project.ilike(like)
                                | KevVulnerability.product.ilike(like))
        if order == "recent":
            query = query.order_by(Alert.created_at.desc(), Alert.id.desc())
        else:
            query = query.order_by(Alert.score.desc(), Alert.id.desc())
        return [_alert(a, k, e) for a, k, e in db.execute(query.limit(limit)).all()]


@router.get("/counts")
def counts():
    """Cantidad por pestaña de la pantalla Alertas."""
    with SessionLocal() as db:
        n = lambda *w: db.scalar(select(func.count()).select_from(Alert).where(*w))  # noqa: E731
        return {"nuevas": n(Alert.created_at >= datetime.now(timezone.utc) - timedelta(days=NEW_DAYS)),
                "enviadas": n(Alert.status.in_(SENT)), "no_enviadas": n(Alert.status.in_(NOT_SENT)),
                "todas": n(), "new_days": NEW_DAYS}


@router.get("/statuses")
def statuses():
    return [{"value": k, "label": v, "manual": k in MANUAL_TARGETS} for k, v in STATUSES.items()]


@router.get("/summary")
def summary():
    with SessionLocal() as db:
        by_status = dict(db.execute(select(Alert.status, func.count()).group_by(Alert.status)).all())
        by_level = dict(db.execute(select(Alert.level, func.count()).group_by(Alert.level)).all())
        last_run = db.scalar(select(CollectorRun).order_by(CollectorRun.id.desc()).limit(1))
        active = ("candidata", "en_revision", "aprobada")
        rows = db.execute(_base_query().where(Alert.status.in_(active))
                          .order_by(Alert.score.desc(), Alert.id.desc()).limit(8)).all()
        upcoming = db.execute(
            _base_query().where(Alert.status.in_(active), KevVulnerability.due_date >= date.today())
            .order_by(KevVulnerability.due_date.asc()).limit(5)).all()
        return {
            "by_status": by_status,
            "by_level": by_level,
            "total": sum(by_status.values()),
            "total_kev": db.scalar(select(func.count()).select_from(KevVulnerability)),
            "last_run": None if not last_run else {
                "status": last_run.status, "catalog_version": last_run.catalog_version,
                "started_at": last_run.started_at, "new": last_run.new_count,
                "updated": last_run.updated_count, "error": last_run.error},
            "top": [_alert(a, k, e) for a, k, e in rows],
            "upcoming_due": [_alert(a, k, e) for a, k, e in upcoming],
        }


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


@router.patch("/{code}/status")
def change_status(code: str, body: StatusIn, user: User = Depends(get_current_user)):
    if body.status not in MANUAL_TARGETS:
        raise HTTPException(400, f"Estado inválido. Opciones: {', '.join(sorted(MANUAL_TARGETS))}")
    with SessionLocal() as db:
        a = db.scalar(select(Alert).where(Alert.code == code.upper()))
        if not a:
            raise HTTPException(404, "Alerta no encontrada")
        if a.status == body.status:
            raise HTTPException(400, "La alerta ya está en ese estado")
        entry = {"fecha": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 "evento": "cambio_estado", "de": a.status, "a": body.status,
                 "usuario": user.email, "comentario": body.comment.strip(), "score": a.score}
        a.status = body.status
        a.history = list(a.history or []) + [entry]
        if body.status in ("descartada", "cerrada"):
            comm = db.scalar(select(Communication).where(Communication.alert_id == a.id, Communication.status == "programado"))
            if comm:
                comm.status = "cancelado"
                a.history = list(a.history) + [{**entry, "evento": "envio_cancelado", "comentario": f"{comm.code} cancelado al {body.status} la alerta"}]
        db.commit()
        row = db.execute(_base_query().where(Alert.id == a.id)).first()
        return _alert(*row, full=True)
