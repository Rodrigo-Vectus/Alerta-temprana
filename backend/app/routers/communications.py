import re
from datetime import date, datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel
from sqlalchemy import select

from app.auth import WRITE_ROLES, get_current_user, require_role
from app.comms import mailer
from app.comms.automation import recipients
from app.comms.content import build_content
from app.comms.fortiguard import lookup as fortiguard_lookup
from app.comms.document import build_docx
from app.comms.newsletter import render_newsletter
from app.comms.pdf import PdfError, docx_to_pdf
from app.db import SessionLocal
from app.usecases import ensure_use_case
from app.models import Alert, Communication, CveEnrichment, KevVulnerability, User

router = APIRouter(prefix="/api/communications", tags=["comunicados"])
DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
REQUIRED = ("subject", "title", "subtitle", "what_happened", "actions", "fortinet", "important",
            "references", "executive_summary", "technical", "status_items", "impact_rows",
            "affected_products", "hardening", "next_steps")


class ContentIn(BaseModel):
    content: dict


class SendTestIn(BaseModel):
    to: str | None = None
    attach_docx: bool = False


def _now():
    return datetime.now(timezone.utc)


class CancelIn(BaseModel):
    reason: str = ""


def _require_write(user: User):
    if user.role not in WRITE_ROLES:
        raise HTTPException(403, "Su rol es de solo lectura")


def _alert_history(alert: Alert, evento: str, user: User, **extra):
    alert.history = list(alert.history or []) + [{
        "fecha": _now().isoformat(timespec="seconds"), "evento": evento, "usuario": user.email,
        "score": alert.score, **extra}]


def _set_alert_status(alert: Alert, new: str, user: User, comment: str):
    if alert.status == new:
        return
    _alert_history(alert, "cambio_estado", user, de=alert.status, a=new, comentario=comment)
    alert.status = new


def _filename(comm: Communication, ext: str):
    cve = comm.content.get("technical", {}).get("cve", "CVE")
    return f"Vectus - Alerta {cve} - {comm.code}.{ext}"


def _summary(comm: Communication, alert: Alert, kev: KevVulnerability):
    return {"code": comm.code, "status": comm.status, "alert_code": alert.code, "alert_status": alert.status,
            "score": alert.score, "cve_id": alert.cve_id, "vendor": kev.vendor_project, "product": kev.product,
            "title": comm.content.get("title"), "subject": comm.content.get("subject"),
            "sends": len(comm.sends or []), "last_send": (comm.sends or [None])[-1],
            "created_by": comm.created_by, "auto": comm.auto, "scheduled_at": comm.scheduled_at,
            "created_at": comm.created_at, "updated_at": comm.updated_at}


def _full(comm: Communication, alert: Alert, kev: KevVulnerability):
    d = _summary(comm, alert, kev)
    d.update(content=comm.content, sends_log=comm.sends or [], updated_by=comm.updated_by,
             clients=sorted({m["client"] for m in (alert.matched_clients or [])}))
    return d


def _load(db, code: str):
    row = db.execute(select(Communication, Alert, KevVulnerability)
                     .join(Alert, Alert.id == Communication.alert_id)
                     .join(KevVulnerability, KevVulnerability.cve_id == Alert.cve_id)
                     .where(Communication.code == code.upper())).first()
    if not row:
        raise HTTPException(404, "Comunicado no encontrado")
    return row


# ------------------------------------------------------------------ consultas
@router.get("")
def list_communications():
    with SessionLocal() as db:
        rows = db.execute(select(Communication, Alert, KevVulnerability)
                          .join(Alert, Alert.id == Communication.alert_id)
                          .join(KevVulnerability, KevVulnerability.cve_id == Alert.cve_id)
                          .order_by(Communication.updated_at.desc())).all()
        return [_summary(*r) for r in rows]


@router.get("/mail-status")
def mail_status():
    return mailer.public_status()


@router.get("/by-alert/{alert_code}")
def by_alert(alert_code: str):
    with SessionLocal() as db:
        alert = db.scalar(select(Alert).where(Alert.code == alert_code.upper()))
        if not alert:
            raise HTTPException(404, "Alerta no encontrada")
        comm = db.scalar(select(Communication).where(Communication.alert_id == alert.id))
        return {"code": comm.code, "status": comm.status} if comm else None


@router.get("/{code}")
def get_communication(code: str):
    with SessionLocal() as db:
        return _full(*_load(db, code))


# ------------------------------------------------------------------ generación y edición
@router.post("/from-alert/{alert_code}")
def create_from_alert(alert_code: str, regenerate: bool = False, user: User = Depends(get_current_user)):
    _require_write(user)
    with SessionLocal() as db:
        alert = db.scalar(select(Alert).where(Alert.code == alert_code.upper()))
        if not alert:
            raise HTTPException(404, "Alerta no encontrada")
        kev = db.get(KevVulnerability, alert.cve_id)
        enr = db.get(CveEnrichment, alert.cve_id)
        comm = db.scalar(select(Communication).where(Communication.alert_id == alert.id))
        if comm and not regenerate:
            return _full(comm, alert, kev)
        content = build_content(kev, enr, alert, fortiguard_lookup(alert.cve_id))
        if comm is None:
            comm = Communication(alert_id=alert.id, content=content, created_by=user.email, updated_by=user.email)
            db.add(comm)
            db.flush()
            comm.code = f"COM-{date.today().year}-{comm.id:04d}"
            _alert_history(alert, "comunicado_generado", user, comentario=comm.code)
        else:
            if comm.status == "enviado":
                raise HTTPException(400, "El comunicado ya fue enviado; no se puede regenerar")
            comm.content, comm.updated_by = content, user.email
            _alert_history(alert, "comunicado_regenerado", user, comentario=comm.code)
        if alert.status in ("candidata", "monitoreo", "descartada_auto"):
            _set_alert_status(alert, "en_revision", user, f"Borrador {comm.code} generado")
        ensure_use_case(db, alert, user.email, content.get("fortiguard"))
        db.commit()
        return _full(comm, alert, kev)


@router.patch("/{code}")
def update_content(code: str, body: ContentIn, user: User = Depends(get_current_user)):
    _require_write(user)
    missing = [k for k in REQUIRED if k not in body.content]
    if missing:
        raise HTTPException(400, f"Faltan campos en el contenido: {', '.join(missing)}")
    with SessionLocal() as db:
        comm, alert, kev = _load(db, code)
        if comm.status == "enviado":
            raise HTTPException(400, "El comunicado ya fue enviado; no se puede editar")
        comm.content = body.content
        comm.updated_by = user.email
        db.commit()
        return _full(comm, alert, kev)


@router.get("/{code}/recipients")
def comm_recipients(code: str):
    with SessionLocal() as db:
        comm, _, _ = _load(db, code)
        rc = recipients(db)
        sent_ok = {to for s in (comm.sends or []) if s.get("tipo") == "clientes" and s.get("ok") for to in s["to"]}
        return [{**r, "sent": r["email"] in sent_ok} for r in rc]


@router.post("/{code}/send-now")
def send_now(code: str, user: User = Depends(get_current_user)):
    """Programa el envío a todos los contactos para ya (el worker lo despacha en menos de un minuto).
    Si ya se envió, reintenta solo los contactos que fallaron o se agregaron después."""
    _require_write(user)
    with SessionLocal() as db:
        comm, alert, kev = _load(db, code)
        if not recipients(db):
            raise HTTPException(400, "No hay contactos activos cargados en Clientes")
        if not mailer.is_configured():
            raise HTTPException(400, "El correo no está configurado en el servidor")
        prev = comm.status
        comm.status, comm.scheduled_at, comm.updated_by = "programado", _now(), user.email
        _alert_history(alert, "envio_manual", user, comentario=f"{comm.code}: envío a clientes solicitado (estado previo: {prev})")
        db.commit()
        return _full(comm, alert, kev)


@router.post("/{code}/cancel")
def cancel(code: str, body: CancelIn | None = None, user: User = Depends(get_current_user)):
    """El SOC decide no enviarlo: se cancela el envío y la alerta pasa a «No enviada».
    El comunicado queda guardado y se puede enviar más adelante si cambia la decisión."""
    _require_write(user)
    reason = (body.reason if body else "").strip()
    with SessionLocal() as db:
        comm, alert, kev = _load(db, code)
        if comm.status != "programado":
            raise HTTPException(400, "Solo se puede cancelar un comunicado programado")
        comm.status, comm.updated_by = "cancelado", user.email
        _alert_history(alert, "envio_cancelado", user,
                       comentario=f"{comm.code} cancelado antes del envío" + (f": {reason}" if reason else ""))
        if alert.status not in ("enviada", "cerrada"):
            _alert_history(alert, "cambio_estado", user, de=alert.status, a="no_enviada", comentario=reason)
            alert.status = "no_enviada"
        db.commit()
        return _full(comm, alert, kev)


@router.delete("/{code}", status_code=204)
def delete_communication(code: str, user: User = Depends(require_role("admin"))):
    """Solo administradores. Borra el comunicado para poder regenerarlo desde la alerta.
    Queda constancia en el historial de la alerta (y en la auditoría) de qué se borró y a cuántos se había enviado."""
    with SessionLocal() as db:
        comm, alert, _ = _load(db, code)
        sent_ok = sorted({to for s in (comm.sends or []) if s.get("tipo") == "clientes" and s.get("ok") for to in s["to"]})
        clients = sorted({s.get("cliente") for s in (comm.sends or []) if s.get("tipo") == "clientes" and s.get("ok") and s.get("cliente")})
        _alert_history(alert, "comunicado_eliminado", user,
                       comentario=f"{comm.code} eliminado (estado: {comm.status}"
                                  + (f", se había enviado a {len(sent_ok)} contacto(s) de {len(clients)} cliente(s): {', '.join(clients)}" if sent_ok else "")
                                  + ")")
        db.delete(comm)
        db.commit()


# ------------------------------------------------------------------ salidas
@router.post("/preview", response_class=HTMLResponse)
def preview(body: ContentIn):
    """Vista previa en vivo del newsletter con el contenido que se está editando (no guarda nada)."""
    try:
        return HTMLResponse(render_newsletter(body.content, mode="data"))
    except Exception as exc:
        raise HTTPException(400, f"No se pudo generar la vista previa: {exc}")


@router.get("/{code}/newsletter", response_class=HTMLResponse)
def newsletter(code: str):
    with SessionLocal() as db:
        comm, _, _ = _load(db, code)
        return HTMLResponse(render_newsletter(comm.content, mode="data"))


@router.get("/{code}/document.docx")
def document_docx(code: str):
    with SessionLocal() as db:
        comm, _, _ = _load(db, code)
        data = build_docx(comm.content)
        return Response(data, media_type=DOCX_MIME,
                        headers={"Content-Disposition": f'attachment; filename="{_filename(comm, "docx")}"'})


@router.get("/{code}/document.pdf")
def document_pdf(code: str, inline: bool = False):
    with SessionLocal() as db:
        comm, _, _ = _load(db, code)
        try:
            pdf = docx_to_pdf(build_docx(comm.content), _filename(comm, "docx"))
        except PdfError as exc:
            raise HTTPException(502, str(exc))
        disp = "inline" if inline else "attachment"
        return Response(pdf, media_type="application/pdf",
                        headers={"Content-Disposition": f'{disp}; filename="{_filename(comm, "pdf")}"'})


@router.post("/{code}/send-test")
def send_test(code: str, body: SendTestIn, user: User = Depends(get_current_user)):
    """Envía el comunicado solo a una dirección de prueba (por defecto, el usuario logueado)."""
    _require_write(user)
    to = (body.to or user.email).strip().lower()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", to):
        raise HTTPException(400, "Email de destino inválido")
    with SessionLocal() as db:
        comm, alert, kev = _load(db, code)
        docx = build_docx(comm.content)
        attachments, warning = [], None
        try:
            attachments.append((_filename(comm, "pdf"), docx_to_pdf(docx, _filename(comm, "docx")), "application/pdf"))
        except PdfError as exc:
            warning = f"No se pudo generar el PDF ({exc}); se adjuntó el DOCX."
            body.attach_docx = True
        if body.attach_docx:
            attachments.append((_filename(comm, "docx"), docx, DOCX_MIME))
        entry = {"fecha": _now().isoformat(timespec="seconds"), "tipo": "prueba", "to": [to],
                 "usuario": user.email, "adjuntos": [a[0] for a in attachments]}
        try:
            mailer.send(comm.content, [to], attachments, subject_prefix="[PRUEBA] ")
            entry["ok"] = True
        except Exception as exc:
            entry.update(ok=False, error=str(exc)[:500])
        comm.sends = list(comm.sends or []) + [entry]
        db.commit()
        if not entry["ok"]:
            raise HTTPException(502, f"No se pudo enviar el mail: {entry['error']}")
        return {"ok": True, "to": to, "attachments": entry["adjuntos"], "warning": warning}
