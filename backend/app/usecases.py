"""Casos de uso SOC (CU-SOC-NNN): un caso por alerta con su flujo, playbook y seguimiento por cliente."""
from datetime import date, datetime, timezone

from sqlalchemy import select

from app.comms.content import classify, product_short
from app.models import (Alert, Client, Communication, CveEnrichment, KevVulnerability, UseCase, UseCaseClient)
from app.settings import get_settings


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ======================================================================= PLAYBOOK
from app.usecase_content import playbook as build_playbook  # noqa: E402


# ======================================================================= CREACIÓN
def sync_clients(db, uc, alert):
    """Agrega al seguimiento los clientes activos que todavía no están (los que reciben las alertas)."""
    have = {r.client_id for r in db.scalars(select(UseCaseClient).where(UseCaseClient.use_case_id == uc.id)).all()}
    exposed = {m["client_id"] for m in (alert.matched_clients or []) if m.get("internet_exposed")}
    uses = {m["client_id"] for m in (alert.matched_clients or [])}
    added = 0
    for cl in db.scalars(select(Client).where(Client.active.is_(True)).order_by(Client.name)).all():
        if cl.id in have:
            continue
        # Si el inventario dice que lo tiene expuesto, se marca; el resto queda para confirmar
        db.add(UseCaseClient(use_case_id=uc.id, client_id=cl.id, client_name=cl.name,
                             exposure="expuesto" if cl.id in exposed else "desconocido",
                             notes="Usa la tecnología según el inventario" if cl.id in uses else None))
        added += 1
    return added


def ensure_use_case(db, alert, user_email="sistema", fg=None):
    uc = db.scalar(select(UseCase).where(UseCase.alert_id == alert.id))
    if uc:
        return uc, False
    kev, enr = db.get(KevVulnerability, alert.cve_id), db.get(CveEnrichment, alert.cve_id)
    if fg is None:
        comm = db.scalar(select(Communication).where(Communication.alert_id == alert.id))
        fg = (comm.content or {}).get("fortiguard") if comm else None
    uc = UseCase(alert_id=alert.id, title=f"{kev.vendor_project} {kev.product} · {alert.cve_id}",
                 playbook=build_playbook(kev, enr, fg), created_by=user_email,
                 history=[{"fecha": now_iso(), "evento": "caso_creado", "usuario": user_email}])
    db.add(uc)
    db.flush()
    uc.code = f"CU-SOC-{uc.id:03d}"
    sync_clients(db, uc, alert)
    alert.history = list(alert.history or []) + [{"fecha": now_iso(), "evento": "caso_creado", "usuario": user_email,
                                                  "score": alert.score, "comentario": uc.code}]
    return uc, True


# ======================================================================= FLUJO
def flow(db, uc, alert):
    """Pasos del flujo CU-SOC con su estado real: done | current | pending | skipped | rejected."""
    cfg = get_settings(db)
    kev = db.get(KevVulnerability, alert.cve_id)
    comm = db.scalar(select(Communication).where(Communication.alert_id == alert.id))
    rows = db.scalars(select(UseCaseClient).where(UseCaseClient.use_case_id == uc.id)).all()
    first = (alert.history or [{}])[0].get("fecha")
    justified = alert.score >= cfg["min_score"] or comm is not None
    sent = [s for s in ((comm.sends if comm else None) or []) if s.get("tipo") == "clientes" and s.get("ok")]
    sent_clients = sorted({s.get("cliente") for s in sent if s.get("cliente")})
    patched = sum(1 for r in rows if r.patch in ("parcheado", "no_aplica"))
    closed = uc.status == "cerrado"

    steps = [
        {"id": "deteccion", "title": "1. Detección automática", "desc": "Consulta a CISA KEV y detección de CVE nueva o actualizada",
         "state": "done", "detail": f"Agregada al catálogo el {kev.date_added:%d/%m/%Y}" if kev and kev.date_added else "", "at": first},
        {"id": "normalizacion", "title": "2. Normalización y deduplicación", "desc": "CVE, producto, fabricante, fecha y estado previo",
         "state": "done", "detail": f"{kev.vendor_project} {kev.product}" if kev else ""},
        {"id": "decision1", "type": "decision", "title": "¿Es una alerta nueva o hay cambios relevantes?", "answer": "si"},
        {"id": "riesgo", "title": "3. Evaluación de riesgo", "desc": "Explotación activa + tipo de falla + exposición + tecnologías de clientes",
         "state": "done", "detail": f"Puntaje {alert.score}/100 (umbral {cfg['min_score']})"},
        {"id": "decision2", "type": "decision", "title": "¿Justifica alerta temprana?", "answer": "si" if justified else "no",
         "no_label": "Monitoreo interno", "si_label": "Generar borrador"},
    ]
    if not justified:
        steps.append({"id": "monitoreo", "title": "Monitoreo interno", "desc": "Conservar evidencia y reevaluar", "state": "current",
                      "detail": "Puntaje por debajo del umbral: no se comunica a clientes"})
    else:
        cstate = comm.status if comm else None
        steps.append({"id": "borrador", "title": "4. Generar borrador", "desc": "Newsletter + informe con el formato Vectus",
                      "state": "done" if comm else "current", "detail": comm.code if comm else "Pendiente de generar", "at": comm.created_at.isoformat() if comm else None})
        validated = cstate in ("enviado",) or (cstate == "programado" and comm.scheduled_at and comm.scheduled_at <= datetime.now(timezone.utc))
        steps.append({"id": "validacion", "title": "5. Validación del SOC", "desc": f"Ventana de revisión de {cfg['delay_minutes']} min: editar, enviar o cancelar",
                      "state": "rejected" if cstate == "cancelado" else "done" if cstate == "enviado" else "current" if cstate in ("programado", "borrador", "aprobado", "error") else "pending",
                      "detail": {"programado": f"Sale a las {comm.scheduled_at.astimezone().strftime('%H:%M')}" if comm and comm.scheduled_at else "",
                                 "cancelado": "Envío cancelado por el SOC", "borrador": "Borrador sin enviar", "error": "El envío falló"}.get(cstate, "")})
        steps.append({"id": "decision3", "type": "decision", "title": "¿Se envía el comunicado?",
                      "answer": "no" if cstate == "cancelado" else "si" if cstate == "enviado" else None,
                      "no_label": "Corregir / cancelar", "si_label": "Enviar alerta"})
        steps.append({"id": "envio", "title": "6. Enviar alerta", "desc": "A todos los contactos de los clientes activos",
                      "state": "done" if sent else "pending",
                      "detail": f"Enviado a {len(sent)} contacto(s) de {len(sent_clients)} cliente(s)" if sent else ""})
    steps.append({"id": "seguimiento", "title": "7. Seguimiento de remediación", "desc": "Exposición, parcheo, mitigaciones e indicadores de compromiso",
                  "state": "done" if closed else "current" if (sent or not justified or rows) and justified else "pending",
                  "detail": f"{patched}/{len(rows)} clientes parcheados o sin impacto" if rows else ""})
    steps.append({"id": "cierre", "title": "8. Cierre y trazabilidad", "desc": "Decisión, evidencias, destinatarios, acciones y estado final",
                  "state": "done" if closed else "pending", "detail": f"Cerrado por {uc.closed_by}" if closed else "",
                  "at": uc.closed_at.isoformat() if uc.closed_at else None})
    return steps


def progress(uc):
    steps = [s for sec in (uc.playbook or []) for s in sec["steps"]]
    return {"done": sum(1 for s in steps if s["done"]), "total": len(steps)}
