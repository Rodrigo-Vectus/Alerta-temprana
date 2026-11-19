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


# ======================================================================= PROCESO SOC
def _section_state(uc, sec_id):
    sec = next((x for x in (uc.playbook or []) if x["id"] == sec_id), None)
    if not sec or not sec["steps"]:
        return "pending", 0, 0
    done = sum(1 for st in sec["steps"] if st["done"])
    return ("done" if done == len(sec["steps"]) else "current" if done else "pending"), done, len(sec["steps"])


def flow(db, uc, alert):
    """Procedimiento operativo del SOC para el caso: quién, en qué plazo, qué hacer y con qué herramienta.
    El estado de cada etapa se calcula con lo registrado (comunicado, playbook, seguimiento por cliente)."""
    from datetime import timedelta
    from app.usecase_content import SLA_HOURS, _ctx, fmt_hours, runbook_titles, severity

    cfg = get_settings(db)
    kev = db.get(KevVulnerability, alert.cve_id)
    enr = db.get(CveEnrichment, alert.cve_id)
    comm = db.scalar(select(Communication).where(Communication.alert_id == alert.id))
    fg = (comm.content or {}).get("fortiguard") if comm else None
    x = _ctx(kev, enr, fg)
    sev = severity(x, alert.score)
    sla = SLA_HOURS[sev]
    titles = runbook_titles(kev, enr, fg)
    rows = db.scalars(select(UseCaseClient).where(UseCaseClient.use_case_id == uc.id)).all()
    total = len(rows)
    classified = sum(1 for r in rows if r.exposure != "desconocido")
    exposed = [r for r in rows if r.exposure == "expuesto"]
    patched = sum(1 for r in rows if r.patch in ("parcheado", "no_aplica"))
    ioc = [r.client_name for r in rows if r.ioc == "con_hallazgos"]
    ioc_checked = sum(1 for r in rows if r.ioc != "no_revisado")
    closed = uc.status == "cerrado"
    start = alert.created_at or datetime.now(timezone.utc)
    now = datetime.now(timezone.utc)

    def due(hours, state):
        if state == "done" or closed:
            return None
        d = start + timedelta(hours=hours)
        return {"at": d.isoformat(), "overdue": now > d}

    sent = [s for s in ((comm.sends if comm else None) or []) if s.get("tipo") == "clientes" and s.get("ok")]
    steps = []

    def step(sid, title, owner, state, actions, links=(), detail="", sla_h=None, kind="step"):
        steps.append({"id": sid, "title": title, "owner": owner, "state": "done" if closed and state != "rejected" else state,
                      "actions": list(actions), "links": list(links), "detail": detail, "kind": kind,
                      "sla": fmt_hours(sla_h) if sla_h else None, "due": due(sla_h, state) if sla_h else None})

    step("deteccion", "Detección y evaluación automática", "Sistema", "done",
         [f"CISA incorporó {alert.cve_id} al catálogo KEV ({kev.date_added:%d/%m/%Y})." if kev and kev.date_added else "CVE incorporada a CISA KEV.",
          f"El motor la evaluó con {alert.score}/100 puntos (umbral {cfg['min_score']}). Severidad operativa: {sev}.",
          "Revisar el «Flujo del ataque» para entender cómo se explota y dónde cortarlo."],
         [{"label": "Ver flujo del ataque", "tab": "ataque"}, {"label": "Ver alerta", "to": f"/alertas/{alert.code}"}])

    tri_state, d, n = _section_state(uc, "alcance")
    tri_state = "done" if tri_state == "done" or (total and classified == total) else ("current" if tri_state == "pending" else tri_state)
    step("triage", "Triage: ¿a quién afecta?", "Analista SOC N1", tri_state,
         [f"Confirmar en qué clientes existe {x['short']} y en qué versión (Runbook › Triage: Wazuh, Defender VM, escáner o comando del producto).",
          "Identificar los activos expuestos a internet y priorizarlos.",
          "Cargar la exposición de cada cliente en «Seguimiento por cliente»."],
         [{"label": "Runbook › Triage", "tab": "runbook", "anchor": "rb-triage"}, {"label": "Seguimiento por cliente", "tab": "clientes"}],
         f"Clientes clasificados: {classified}/{total}", sla["triage"])

    if comm:
        cst = comm.status
        cstate = {"enviado": "done", "cancelado": "rejected", "programado": "current", "error": "current"}.get(cst, "current")
        detail = {"enviado": f"Enviado a {len(sent)} contacto(s)", "cancelado": "Envío cancelado por el SOC",
                  "programado": f"Sale automáticamente a las {comm.scheduled_at.astimezone().strftime('%H:%M')}" if comm.scheduled_at else "Programado",
                  "error": "El último envío falló"}.get(cst, "Borrador sin enviar")
    else:
        cstate, detail = "current", "Todavía no se generó"
    step("comunicado", "Aviso preventivo a clientes", "SOC (revisión) · Sistema (envío)", cstate,
         ["Revisar el comunicado (newsletter + informe) durante la ventana de revisión: datos técnicos, pasos y sección Fortinet.",
          "Enviar una prueba a un buzón interno si se modificó el texto.",
          "Cancelar el envío si la vulnerabilidad no aplica a la cartera; si aplica, dejar que salga o usar «Enviar ahora»."],
         [{"label": "Abrir comunicado", "to": f"/comunicados/{comm.code}"}] if comm else [{"label": "Generar desde la alerta", "to": f"/alertas/{alert.code}"}],
         detail, kind="step")

    h_state, d, n = _section_state(uc, "deteccion")
    step("hunting", "Hunting en el SIEM de cada cliente", "Analista SOC N2", h_state if h_state != "pending" else "current",
         ["Ejecutar en el SIEM / consola de cada cliente las consultas del Runbook, eligiendo su herramienta (Splunk, Sentinel, Wazuh, FortiSIEM, QRadar…):"]
         + [f"• {t}" for t in titles["hunting"]]
         + ["Registrar en «Seguimiento por cliente» el resultado de indicadores de compromiso (sin hallazgos / con hallazgos)."],
         [{"label": "Runbook › Hunting", "tab": "runbook", "anchor": "rb-hunting"}, {"label": "Playbook › Detección", "tab": "playbook"}],
         f"Clientes revisados: {ioc_checked}/{total} · Pasos del playbook: {d}/{n}", sla["triage"] + sla["contencion"])

    step("contacto", "Contacto con los clientes expuestos", "Analista SOC / Ejecutivo de cuenta",
         "done" if exposed and all(r.notes for r in exposed) else ("current" if exposed else ("done" if total and classified == total else "pending")),
         [f"Llamar o escribir al responsable técnico de cada cliente expuesto ({len(exposed)}) para confirmar la exposición y acordar la ventana de parche.",
          "Ofrecer la activación de controles compensatorios (IPS/WAF, bloqueo de puertos, aislamiento).",
          "Dejar en «Notas» del seguimiento: con quién se habló, qué se acordó y el número de ticket."],
         [{"label": "Seguimiento por cliente", "tab": "clientes"}, {"label": "Contactos de clientes", "to": "/clientes"}],
         ", ".join(r.client_name for r in exposed) or "Sin clientes marcados como expuestos")

    c_state, d, n = _section_state(uc, "contencion")
    step("contencion", "Contención mientras no hay parche", "Analista SOC N2 / Ingeniería", c_state if exposed or c_state != "pending" else "pending",
         ["En los clientes expuestos y sin parche, aplicar los bloqueos del Runbook según su equipamiento (FortiGate, Palo Alto, Cisco, Check Point…):"]
         + [f"• {t}" for t in titles["contencion"]]
         + ["Documentar cada regla temporal (equipo, hora, responsable) para revertirla después del parche."],
         [{"label": "Runbook › Contención", "tab": "runbook", "anchor": "rb-contencion"}, {"label": "Playbook › Contención", "tab": "playbook"}],
         f"Pasos del playbook: {d}/{n}", sla["contencion"])

    r_state = "done" if total and patched == total else ("current" if patched or exposed else "pending")
    step("remediacion", "Parche y verificación", "Cliente (aplica) · SOC (verifica)", r_state,
         [f"Seguir la aplicación de la actualización de {x['vendor']} en cada cliente.",
          "Verificar la versión final con el comando o escáner del Runbook y repetir el hunting a los 7 días.",
          "Marcar «Parcheado» o «No aplica» en el seguimiento y quitar las reglas temporales de contención."],
         [{"label": "Runbook › Verificación", "tab": "runbook", "anchor": "rb-verificacion"}, {"label": "Seguimiento por cliente", "tab": "clientes"}],
         f"Parcheados o sin impacto: {patched}/{total}", sla["parche_expuestos"])

    steps.append({"id": "decision_ioc", "kind": "decision", "title": "¿Se encontraron indicios de compromiso?",
                  "answer": "si" if ioc else ("no" if total and ioc_checked == total else None),
                  "si_label": "Escalar a incidente", "no_label": "Continuar al cierre",
                  "detail": ("Con hallazgos: " + ", ".join(ioc)) if ioc else ""})
    if ioc:
        step("incidente", "Respuesta a incidente", "Líder SOC / IR", "current",
             ["Declarar incidente para cada cliente con hallazgos y notificar a su contacto y a la gerencia de Vectus.",
              "Aislar los equipos afectados y preservar evidencias (Runbook › Evidencias) antes de remediar.",
              "Si hay ransomware o exfiltración, evaluar obligaciones legales de notificación (Runbook › Escalamiento)."],
             [{"label": "Runbook › Evidencias", "tab": "runbook", "anchor": "rb-evidencias"}, {"label": "Runbook › Escalamiento", "tab": "runbook", "anchor": "rb-escalamiento"}],
             ", ".join(ioc))

    step("cierre", "Cierre del caso", "Líder SOC", "done" if closed else "pending",
         ["Verificar los criterios de cierre del Runbook: todos los clientes clasificados, parcheados o con excepción documentada.",
          "Cargar notas de cierre con resultado y lecciones aprendidas, y cerrar el caso."],
         [{"label": "Runbook › Criterios de cierre", "tab": "runbook", "anchor": "rb-cierre"}],
         f"Cerrado por {uc.closed_by}" if closed else "")
    return {"severity": sev, "steps": steps}


def progress(uc):
    steps = [s for sec in (uc.playbook or []) for s in sec["steps"]]
    return {"done": sum(1 for s in steps if s["done"]), "total": len(steps)}
