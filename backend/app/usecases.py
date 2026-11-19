"""Casos de uso SOC (CU-SOC-NNN): un caso por alerta con su flujo, playbook y seguimiento por cliente."""
from datetime import date, datetime, timezone

from sqlalchemy import select

from app.comms.content import classify, product_short
from app.models import (Alert, Client, Communication, CveEnrichment, KevVulnerability, UseCase, UseCaseClient)
from app.settings import get_settings


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ======================================================================= PLAYBOOK
DETECT_HUNT = {
    "web": ["Revisar los logs de acceso del servidor web y del WAF en busca de peticiones anómalas dirigidas a {short} (parámetros extraños, codificaciones inusuales, rutas de administración).",
            "Buscar archivos creados o modificados recientemente en los directorios publicados (posibles web shells)."],
    "perimetral": ["Revisar en los logs de {short} los accesos administrativos, inicios de sesión VPN y cambios de configuración de los últimos 30 días.",
                   "Verificar que no existan cuentas locales, reglas o certificados nuevos que no hayan sido creados por el equipo."],
    "correo": ["Buscar en el gateway de correo los mensajes con adjuntos o archivos de mensaje (.msg, .eml) recibidos desde la fecha de publicación.",
               "Revisar conexiones salientes SMB/WebDAV desde estaciones de trabajo hacia internet (indicio de filtración de hashes NTLM)."],
    "navegador": ["Revisar procesos hijos inusuales lanzados por el navegador (PowerShell, cmd, scripts) en las estaciones.",
                  "Buscar en el proxy/filtrado web accesos a dominios recién registrados o clasificados como maliciosos."],
    "virtualizacion": ["Revisar los logs de vCenter/ESXi o de la plataforma de backup: inicios de sesión, creación de usuarios y comandos ejecutados.",
                       "Verificar la integridad de las copias de seguridad y que no haya trabajos borrados o modificados."],
    "so": ["Revisar en los equipos afectados la creación de servicios, tareas programadas y cuentas nuevas.",
           "Buscar ejecución de binarios desde rutas temporales o de usuario."],
    "general": ["Revisar los registros de {short} en busca de errores, accesos o comandos inusuales desde la fecha de publicación."],
}
CONTAIN = {
    "web": "Si no se puede parchear de inmediato, publicar {short} detrás del WAF (parcheo virtual) o restringir el acceso desde internet.",
    "perimetral": "Restringir la administración y la VPN de {short} a direcciones IP de confianza y deshabilitar los servicios expuestos que no se usen.",
    "correo": "Bloquear en el gateway los tipos de adjunto de riesgo y el tráfico SMB/NTLM saliente (TCP 445) en el firewall.",
    "navegador": "Forzar la actualización de los navegadores y bloquear sitios maliciosos con el filtrado web.",
    "virtualizacion": "Aislar las interfaces de administración en una red de gestión y limitar el acceso a los administradores.",
    "so": "Aislar de la red los equipos con indicios de compromiso hasta completar la revisión.",
    "general": "Aplicar las mitigaciones indicadas por el fabricante o aislar el sistema afectado hasta parchear.",
}
IOC = {
    "rce": ["Procesos hijos inesperados del servicio afectado (shells, PowerShell, curl/wget).", "Archivos nuevos en directorios del servicio (web shells, binarios).", "Conexiones salientes del servidor hacia IPs desconocidas."],
    "creds": ["Inicios de sesión desde ubicaciones o equipos inusuales.", "Uso de cuentas fuera de horario o desde varios lugares a la vez.", "Conexiones SMB/NTLM salientes hacia internet."],
    "auth": ["Accesos administrativos sin un inicio de sesión previo válido.", "Cuentas o tokens creados recientemente.", "Cambios de configuración no planificados."],
    "priv": ["Cuentas agregadas a grupos privilegiados.", "Servicios o tareas programadas nuevas con privilegios elevados."],
    "mem": ["Caídas o reinicios inesperados del servicio.", "Procesos hijos inusuales tras una caída."],
    "web": ["Peticiones a recursos internos desde el servidor web (SSRF).", "Archivos subidos o modificados en el sitio."],
}


def _step(sid, text):
    return {"id": sid, "text": text, "done": False, "done_by": None, "done_at": None}


def build_playbook(kev, enr, fg=None):
    c = classify(kev, enr)
    short = product_short(kev.vendor_project, kev.product)
    s, fam = c["surface"], c["family"]
    fmt = lambda t: t.format(short=short, cve=kev.cve_id)
    sections = []

    sections.append({"id": "alcance", "title": "1. Alcance y exposición", "steps": [
        _step("alcance-1", f"Identificar en cada cliente los activos con {short} y su versión."),
        _step("alcance-2", f"Comparar las versiones instaladas con las afectadas según el aviso del fabricante para {kev.cve_id}."),
        _step("alcance-3", "Determinar cuáles están expuestos a internet y priorizarlos."),
    ]})

    det = []
    if fg and fg.get("ips"):
        names = ", ".join(f"{x['name']}" + (f" (ID {x['id']})" if x.get("id") else "") for x in fg["ips"][:3])
        det.append(_step("det-ips", f"Verificar que la firma IPS de FortiGuard {names} esté activa (acción: bloquear) en los perfiles IPS de los FortiGate que protegen {short}."))
        det.append(_step("det-faz", f"En FortiAnalyzer/FortiSIEM, buscar eventos IPS con la firma {fg['ips'][0]['name']} de los últimos 30 días para detectar intentos previos."))
    else:
        det.append(_step("det-ips", f"Verificar que el perfil IPS de los FortiGate que protegen {short} esté actualizado y en modo bloqueo."))
    if fg and fg.get("endpoint"):
        det.append(_step("det-ems", f"En FortiClient EMS, listar los equipos detectados con la vulnerabilidad «{fg['endpoint'][0]['name']}»."))
    if fg and fg.get("dast"):
        det.append(_step("det-dast", f"Escanear con FortiDAST las aplicaciones web publicadas para confirmar la exposición a {kev.cve_id}."))
    for i, t in enumerate(DETECT_HUNT.get(s, DETECT_HUNT["general"]), 1):
        det.append(_step(f"det-hunt-{i}", fmt(t)))
    sections.append({"id": "deteccion", "title": "2. Detección y búsqueda de amenazas", "steps": det})

    cont = [_step("cont-1", fmt(CONTAIN.get(s, CONTAIN["general"])))]
    if fg and fg.get("virus"):
        cont.append(_step("cont-av", "Confirmar que el antivirus de FortiGuard esté actualizado en FortiGate, FortiMail y FortiEDR (detecta " +
                          ", ".join(x["name"] for x in sorted(fg["virus"], key=lambda v: 0 if "ransom" in v["name"].lower() else 1)[:2]) + ")."))
    cont.append(_step("cont-iso", "Si se detecta compromiso, aislar el equipo (FortiEDR / FortiNAC) y preservar evidencia antes de remediar."))
    sections.append({"id": "contencion", "title": "3. Contención", "steps": cont})

    rem = [_step("rem-1", f"Aplicar la actualización o mitigación de {kev.vendor_project} en todos los activos identificados."),
           _step("rem-2", "Documentar por cliente la fecha de aplicación y la versión final.")]
    if fam in ("creds", "auth"):
        rem.append(_step("rem-cred", "Rotar las credenciales y tokens que pudieron exponerse, empezando por cuentas privilegiadas."))
    if (kev.known_ransomware or "").lower() == "known":
        rem.append(_step("rem-bkp", "Verificar copias de seguridad recientes, aisladas y restaurables (uso conocido en ransomware)."))
    sections.append({"id": "remediacion", "title": "4. Erradicación y remediación", "steps": rem})

    sections.append({"id": "verificacion", "title": "5. Verificación y cierre", "steps": [
        _step("ver-1", "Confirmar que la versión instalada ya no es vulnerable (reescaneo o verificación manual)."),
        _step("ver-2", "Mantener el monitoreo reforzado de los activos durante 30 días."),
        _step("ver-3", "Registrar lecciones aprendidas y cerrar el caso."),
    ]})

    iocs = IOC.get(fam, IOC["rce"])
    sections.append({"id": "ioc", "title": "Indicadores de compromiso a revisar", "steps": [_step(f"ioc-{i}", t) for i, t in enumerate(iocs, 1)]})
    return sections


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
