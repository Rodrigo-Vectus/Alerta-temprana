from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import func, select

from app.auth import WRITE_ROLES, get_current_user
from app.db import SessionLocal
from app.models import Alert, Communication, CveEnrichment, KevVulnerability, UseCase, UseCaseClient, User
from app.usecase_content import attack_flow, playbook as build_playbook, runbook, runbook_markdown
from app.usecases import ensure_use_case, flow, now_iso, progress, sync_clients

router = APIRouter(prefix="/api/usecases", tags=["casos de uso"])
EXPOSURE = {"desconocido", "expuesto", "no_expuesto"}
PATCH = {"pendiente", "en_curso", "parcheado", "no_aplica"}
IOC = {"no_revisado", "sin_hallazgos", "con_hallazgos"}


class StepIn(BaseModel):
    done: bool


class ClientIn(BaseModel):
    exposure: str | None = None
    patch: str | None = None
    ioc: str | None = None
    notes: str | None = None


class CloseIn(BaseModel):
    notes: str = ""


def _w(user):
    if user.role not in WRITE_ROLES:
        raise HTTPException(403, "Su rol es de solo lectura")


def _load(db, code):
    row = db.execute(select(UseCase, Alert, KevVulnerability)
                     .join(Alert, Alert.id == UseCase.alert_id)
                     .join(KevVulnerability, KevVulnerability.cve_id == Alert.cve_id)
                     .where(UseCase.code == code.upper())).first()
    if not row:
        raise HTTPException(404, "Caso de uso no encontrado")
    return row


def _clients(db, uc):
    rows = db.scalars(select(UseCaseClient).where(UseCaseClient.use_case_id == uc.id).order_by(UseCaseClient.client_name)).all()
    return [{"id": r.id, "client_id": r.client_id, "client": r.client_name, "exposure": r.exposure, "patch": r.patch,
             "ioc": r.ioc, "notes": r.notes, "updated_by": r.updated_by, "updated_at": r.updated_at} for r in rows]


def _summary(db, uc, alert, kev):
    rows = _clients(db, uc)
    return {"code": uc.code, "status": uc.status, "title": uc.title, "alert_code": alert.code, "alert_status": alert.status,
            "cve_id": alert.cve_id, "score": alert.score, "vendor": kev.vendor_project, "product": kev.product,
            "progress": progress(uc),
            "clients": {"total": len(rows), "patched": sum(r["patch"] in ("parcheado", "no_aplica") for r in rows),
                        "exposed": sum(r["exposure"] == "expuesto" for r in rows), "ioc": sum(r["ioc"] == "con_hallazgos" for r in rows)},
            "created_at": uc.created_at, "updated_at": uc.updated_at, "closed_at": uc.closed_at}


def _fg(db, alert):
    comm = db.scalar(select(Communication).where(Communication.alert_id == alert.id))
    return comm, ((comm.content or {}).get("fortiguard") if comm else None)


def _refs(comm, kev):
    if comm and (comm.content or {}).get("references"):
        return comm.content["references"]
    return [{"label": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{kev.cve_id}"},
            {"label": "CISA KEV", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}]


def _full(db, uc, alert, kev):
    comm, fg = _fg(db, alert)
    enr = db.get(CveEnrichment, alert.cve_id)
    d = _summary(db, uc, alert, kev)
    d.update(flow=flow(db, uc, alert), attack=attack_flow(kev, enr, fg), runbook=runbook(kev, enr, fg, alert, _refs(comm, kev)), playbook=uc.playbook, client_rows=_clients(db, uc), history=uc.history,
             closure_notes=uc.closure_notes, closed_by=uc.closed_by, created_by=uc.created_by,
             communication={"code": comm.code, "status": comm.status} if comm else None,
             alert_name=((comm.content or {}).get("title") if comm else None) or kev.vulnerability_name)
    return d


def _log(uc, evento, user, **extra):
    uc.history = list(uc.history or []) + [{"fecha": now_iso(), "evento": evento, "usuario": user.email, **extra}]


@router.get("")
def list_usecases():
    with SessionLocal() as db:
        rows = db.execute(select(UseCase, Alert, KevVulnerability).join(Alert, Alert.id == UseCase.alert_id)
                          .join(KevVulnerability, KevVulnerability.cve_id == Alert.cve_id)
                          .order_by(UseCase.status, UseCase.updated_at.desc())).all()
        return [_summary(db, *r) for r in rows]


@router.get("/by-alert/{alert_code}")
def by_alert(alert_code: str):
    with SessionLocal() as db:
        a = db.scalar(select(Alert).where(Alert.code == alert_code.upper()))
        uc = db.scalar(select(UseCase).where(UseCase.alert_id == a.id)) if a else None
        return {"code": uc.code, "status": uc.status} if uc else None


@router.post("/from-alert/{alert_code}")
def create(alert_code: str, user: User = Depends(get_current_user)):
    _w(user)
    with SessionLocal() as db:
        a = db.scalar(select(Alert).where(Alert.code == alert_code.upper()))
        if not a:
            raise HTTPException(404, "Alerta no encontrada")
        uc, _ = ensure_use_case(db, a, user.email)
        db.commit()
        return _full(db, *_load(db, uc.code))


@router.get("/{code}")
def get(code: str):
    with SessionLocal() as db:
        return _full(db, *_load(db, code))


@router.patch("/{code}/steps/{step_id}")
def toggle_step(code: str, step_id: str, body: StepIn, user: User = Depends(get_current_user)):
    _w(user)
    with SessionLocal() as db:
        uc, a, k = _load(db, code)
        pb, found = [dict(sec, steps=[dict(s) for s in sec["steps"]]) for sec in uc.playbook], None
        for sec in pb:
            for s in sec["steps"]:
                if s["id"] == step_id:
                    s.update(done=body.done, done_by=user.email if body.done else None, done_at=now_iso() if body.done else None)
                    found = s
        if not found:
            raise HTTPException(404, "Paso no encontrado")
        uc.playbook = pb
        _log(uc, "paso_completado" if body.done else "paso_reabierto", user, paso=found["text"][:120])
        db.commit()
        return _full(db, uc, a, k)


@router.patch("/{code}/clients/{row_id}")
def update_client(code: str, row_id: int, body: ClientIn, user: User = Depends(get_current_user)):
    _w(user)
    for val, allowed in ((body.exposure, EXPOSURE), (body.patch, PATCH), (body.ioc, IOC)):
        if val is not None and val not in allowed:
            raise HTTPException(400, f"Valor inválido: {val}")
    with SessionLocal() as db:
        uc, a, k = _load(db, code)
        r = db.get(UseCaseClient, row_id)
        if not r or r.use_case_id != uc.id:
            raise HTTPException(404, "Cliente no encontrado en el caso")
        changes = {f: v for f, v in body.model_dump(exclude_none=True).items() if getattr(r, f) != v}
        for f, v in changes.items():
            setattr(r, f, v)
        r.updated_by = user.email
        if changes:
            _log(uc, "seguimiento_cliente", user, cliente=r.client_name, cambios=changes)
        db.commit()
        return _full(db, uc, a, k)


@router.post("/{code}/sync-clients")
def sync(code: str, user: User = Depends(get_current_user)):
    _w(user)
    with SessionLocal() as db:
        uc, a, k = _load(db, code)
        n = sync_clients(db, uc, a)
        if n:
            _log(uc, "clientes_agregados", user, cantidad=n)
        db.commit()
        return _full(db, uc, a, k)


@router.post("/{code}/close")
def close(code: str, body: CloseIn, user: User = Depends(get_current_user)):
    _w(user)
    with SessionLocal() as db:
        uc, a, k = _load(db, code)
        if uc.status == "cerrado":
            raise HTTPException(400, "El caso ya está cerrado")
        uc.status, uc.closed_by, uc.closed_at, uc.closure_notes = "cerrado", user.email, datetime.now(timezone.utc), body.notes.strip() or None
        _log(uc, "caso_cerrado", user, comentario=body.notes.strip())
        if a.status != "cerrada":
            a.history = list(a.history or []) + [{"fecha": now_iso(), "evento": "cambio_estado", "de": a.status, "a": "cerrada",
                                                  "usuario": user.email, "score": a.score, "comentario": f"{uc.code} cerrado"}]
            a.status = "cerrada"
        db.commit()
        return _full(db, uc, a, k)


@router.post("/{code}/reopen")
def reopen(code: str, user: User = Depends(get_current_user)):
    _w(user)
    with SessionLocal() as db:
        uc, a, k = _load(db, code)
        uc.status, uc.closed_by, uc.closed_at = "abierto", None, None
        _log(uc, "caso_reabierto", user)
        if a.status == "cerrada":
            a.history = list(a.history or []) + [{"fecha": now_iso(), "evento": "cambio_estado", "de": "cerrada", "a": "en_revision",
                                                  "usuario": user.email, "score": a.score, "comentario": f"{uc.code} reabierto"}]
            a.status = "en_revision"
        db.commit()
        return _full(db, uc, a, k)


@router.get("/{code}/runbook.md")
def runbook_md(code: str):
    with SessionLocal() as db:
        uc, a, k = _load(db, code)
        comm, fg = _fg(db, a)
        md = runbook_markdown(uc.code, f"{k.vendor_project} {k.product} · {a.cve_id}",
                              runbook(k, db.get(CveEnrichment, a.cve_id), fg, a, _refs(comm, k)))
        return Response(md, media_type="text/markdown; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="Runbook {uc.code} {a.cve_id}.md"'})


@router.post("/{code}/rebuild-playbook")
def rebuild_playbook(code: str, user: User = Depends(get_current_user)):
    """Vuelve a armar el playbook con la plantilla actual, conservando los pasos ya tildados."""
    _w(user)
    with SessionLocal() as db:
        uc, a, k = _load(db, code)
        _, fg = _fg(db, a)
        done = {s["id"]: s for sec in (uc.playbook or []) for s in sec["steps"] if s.get("done")}
        pb = build_playbook(k, db.get(CveEnrichment, a.cve_id), fg)
        for sec in pb:
            for s in sec["steps"]:
                if s["id"] in done:
                    s.update(done=True, done_by=done[s["id"]]["done_by"], done_at=done[s["id"]]["done_at"])
        uc.playbook = pb
        _log(uc, "playbook_actualizado", user)
        db.commit()
        return _full(db, uc, a, k)
