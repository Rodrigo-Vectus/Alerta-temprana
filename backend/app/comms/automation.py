"""Envío automático de comunicados.

Flujo:
  1. El motor detecta una CVE NUEVA en CISA KEV con puntaje >= umbral.
  2. Se genera el comunicado y queda "programado" para dentro de N minutos (ventana del SOC).
  3. El SOC recibe en ese momento el mismo mail que verán los clientes, con un aviso y el link
     a la consola para editarlo o cancelarlo.
  4. Cumplida la ventana, el worker lo envía a todos los contactos activos de los clientes activos
     (un mail por contacto, para no exponer las direcciones de otros clientes).
"""
import logging
import os
import time
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import select

from app.comms import mailer
from app.comms.content import build_content
from app.comms.fortiguard import lookup as fortiguard_lookup
from app.comms.document import build_docx
from app.comms.pdf import PdfError, docx_to_pdf
from app.db import SessionLocal
from app.models import Alert, Client, ClientContact, Communication, CveEnrichment, KevVulnerability
from app.settings import get_settings
from app.usecases import ensure_use_case

log = logging.getLogger("automation")
DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
def _tz():
    for name in (os.getenv("TZ", ""), "America/Argentina/Buenos_Aires"):
        try:
            return ZoneInfo(name) if name else None
        except Exception:
            continue
    return timezone(timedelta(hours=-3))


TZ = _tz() or timezone(timedelta(hours=-3))
SEND_PAUSE = float(os.getenv("MAIL_SEND_PAUSE_SECONDS", "1.5"))   # pausa entre mails (límites de Gmail)


def now_utc():
    return datetime.now(timezone.utc)


def local_hhmm(dt):
    return dt.astimezone(TZ).strftime("%H:%M")


def recipients(db):
    """Contactos activos de clientes activos, sin duplicados."""
    rows = db.execute(select(ClientContact.email, ClientContact.name, Client.name)
                      .join(Client, Client.id == ClientContact.client_id)
                      .where(Client.active.is_(True), ClientContact.active.is_(True))
                      .order_by(Client.name, ClientContact.email)).all()
    seen, out = set(), []
    for email, name, client in rows:
        if email not in seen:
            seen.add(email)
            out.append({"email": email, "name": name, "client": client})
    return out


def filename(comm, ext):
    cve = comm.content.get("technical", {}).get("cve", "CVE")
    return f"Vectus - Alerta {cve} - {comm.code}.{ext}"


def build_attachments(comm, attach_docx=False):
    docx = build_docx(comm.content)
    atts, warning = [], None
    try:
        atts.append((filename(comm, "pdf"), docx_to_pdf(docx, filename(comm, "docx")), "application/pdf"))
    except PdfError as exc:
        warning = str(exc)
        attach_docx = True
    if attach_docx:
        atts.append((filename(comm, "docx"), docx, DOCX_MIME))
    return atts, warning


def _history(alert, evento, **extra):
    alert.history = list(alert.history or []) + [{
        "fecha": now_utc().isoformat(timespec="seconds"), "evento": evento, "usuario": "sistema",
        "score": alert.score, **extra}]


def _set_alert(alert, new, comment):
    if alert.status != new:
        _history(alert, "cambio_estado", de=alert.status, a=new, comentario=comment)
        alert.status = new


# ----------------------------------------------------------------- 1. programar
def schedule_for_results(results: list[dict]):
    """Recibe la salida de scoring.process_pending y programa los comunicados que correspondan."""
    if not results:
        return []
    created = []
    with SessionLocal() as db:
        cfg = get_settings(db)
        if not cfg["auto_send"]:
            return []
        for r in results:
            if r.get("trigger") != "nueva_en_kev" or r.get("status") != "candidata" or r.get("score", 0) < cfg["min_score"]:
                continue
            alert = db.scalar(select(Alert).where(Alert.code == r["code"]))
            if not alert or db.scalar(select(Communication).where(Communication.alert_id == alert.id)):
                continue
            kev, enr = db.get(KevVulnerability, alert.cve_id), db.get(CveEnrichment, alert.cve_id)
            when = now_utc() + timedelta(minutes=int(cfg["delay_minutes"]))
            comm = Communication(alert_id=alert.id, content=build_content(kev, enr, alert, fortiguard_lookup(alert.cve_id)), status="programado",
                                 scheduled_at=when, auto=True, created_by="sistema", updated_by="sistema")
            db.add(comm)
            db.flush()
            comm.code = f"COM-{date.today().year}-{comm.id:04d}"
            _history(alert, "comunicado_programado", comentario=f"{comm.code} · envío automático {local_hhmm(when)}")
            _set_alert(alert, "en_revision", f"Envío automático programado ({comm.code})")
            ensure_use_case(db, alert, "sistema", (comm.content or {}).get("fortiguard"))
            db.commit()
            log.warning("COMUNICADO PROGRAMADO %s para %s (%s)", comm.code, local_hhmm(when), alert.code)
            created.append(comm.code)
            notify_soc(db, comm, cfg)
    return created


def notify_soc(db, comm, cfg):
    """Envía al SOC el mismo mail que recibirán los clientes, con el aviso de la ventana de cancelación."""
    soc = cfg.get("soc_emails") or []
    if not soc or not mailer.is_configured():
        return
    rcpts = recipients(db)
    when = local_hhmm(comm.scheduled_at) if comm.scheduled_at else "—"
    notice = {
        "text": (f"Este comunicado se enviará automáticamente a las {when} a {len(rcpts)} contacto(s) "
                 f"de {len({r['client'] for r in rcpts})} cliente(s). Si hay que corregirlo o frenarlo, hacelo desde la consola antes de esa hora."),
        "url": f"{cfg['public_url']}/comunicados/{comm.code}",
    }
    atts, _ = build_attachments(comm, cfg.get("attach_docx", False))
    entry = {"fecha": now_utc().isoformat(timespec="seconds"), "tipo": "aviso_soc", "to": soc,
             "usuario": "sistema", "adjuntos": [a[0] for a in atts]}
    try:
        mailer.send(comm.content, soc, atts, subject_prefix=f"[SAT · sale {when}] ", notice=notice)
        entry["ok"] = True
    except Exception as exc:
        entry.update(ok=False, error=str(exc)[:500])
        log.error("No se pudo avisar al SOC de %s: %s", comm.code, exc)
    comm.sends = list(comm.sends or []) + [entry]
    db.commit()


# ----------------------------------------------------------------- 2. despachar
def dispatch_due():
    """Envía los comunicados programados cuya hora ya llegó. Lo llama el worker cada ~30 s."""
    sent = []
    with SessionLocal() as db:
        due = db.scalars(select(Communication)
                         .where(Communication.status == "programado", Communication.scheduled_at <= now_utc())
                         .order_by(Communication.scheduled_at)
                         .with_for_update(skip_locked=True)).all()
        for comm in due:
            sent.append(_dispatch(db, comm))
    return sent


def _dispatch(db, comm):
    cfg = get_settings(db)
    alert = db.get(Alert, comm.alert_id)
    already = {to for s in (comm.sends or []) if s.get("tipo") == "clientes" and s.get("ok") for to in s["to"]}
    pending = [r for r in recipients(db) if r["email"] not in already]
    if not mailer.is_configured():
        comm.status = "error"
        comm.sends = list(comm.sends or []) + [{"fecha": now_utc().isoformat(timespec="seconds"), "tipo": "clientes",
                                                "to": [], "usuario": "sistema", "ok": False, "error": "El correo no está configurado"}]
        db.commit()
        return {"code": comm.code, "status": "error"}
    if not pending and not already:
        comm.status = "error"
        comm.sends = list(comm.sends or []) + [{"fecha": now_utc().isoformat(timespec="seconds"), "tipo": "clientes",
                                                "to": [], "usuario": "sistema", "ok": False, "error": "No hay contactos activos cargados en Clientes"}]
        db.commit()
        return {"code": comm.code, "status": "error"}

    if alert:
        uc, created = ensure_use_case(db, alert, "sistema", (comm.content or {}).get("fortiguard"))
        if created:
            db.commit()
            log.info("%s: caso de uso %s creado al enviar", comm.code, uc.code)
    atts, warning = build_attachments(comm, cfg.get("attach_docx", False))
    if warning:
        log.warning("%s: %s", comm.code, warning)
    ok = len(already)
    for r in pending:
        entry = {"fecha": now_utc().isoformat(timespec="seconds"), "tipo": "clientes", "to": [r["email"]],
                 "cliente": r["client"], "usuario": "sistema", "adjuntos": [a[0] for a in atts]}
        try:
            mailer.send(comm.content, [r["email"]], atts)
            entry["ok"] = True
            ok += 1
        except Exception as exc:
            entry.update(ok=False, error=str(exc)[:500])
            log.error("%s → %s falló: %s", comm.code, r["email"], exc)
        comm.sends = list(comm.sends or []) + [entry]
        db.commit()
        time.sleep(SEND_PAUSE)

    failed = len(pending) - (ok - len(already))
    comm.status = "enviado" if ok else "error"
    if alert and ok:
        _set_alert(alert, "enviada", f"{comm.code} enviado a {ok} contacto(s)" + (f", {failed} con error" if failed else ""))
    db.commit()
    log.warning("COMUNICADO %s ENVIADO: %s ok, %s con error", comm.code, ok, failed)
    return {"code": comm.code, "status": comm.status, "ok": ok, "failed": failed}
