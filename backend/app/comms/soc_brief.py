"""Mail técnico para el equipo SOC: qué hacer con cada caso de uso, sin entrar a la consola.

Contenido: plazos según la severidad, el proceso SOC etapa por etapa (responsable, plazo y
acciones), el checklist del playbook, cómo se explota y dónde cortarlo, y el runbook completo
(consultas por SIEM, firewall y EDR) como adjunto.

Lo envía el worker automáticamente para cada caso nuevo (si está activado en Configuración)
y se puede reenviar desde el caso con «Enviar playbook por mail».
"""
import logging
from datetime import datetime, timezone
from html import escape
from zoneinfo import ZoneInfo

from sqlalchemy import select

from app.comms import mailer
from app.models import Alert, Communication, CveEnrichment, KevVulnerability, UseCase
from app.settings import get_settings
from app.usecase_content import attack_flow, runbook, runbook_markdown
from app.usecases import flow, now_iso

log = logging.getLogger("soc_brief")

try:
    import os
    TZ = ZoneInfo(os.getenv("TZ") or "America/Argentina/Buenos_Aires")
except Exception:  # noqa: BLE001
    TZ = timezone.utc

SEV_COLOR = {"Crítica": "#b91c1c", "Alta": "#c2410c"}
OWNER_BG = "#eef4ff"


def _when(iso: str | None) -> str:
    if not iso:
        return ""
    d = datetime.fromisoformat(iso).astimezone(TZ)
    return d.strftime("%d/%m %H:%M") + " hs"


def _refs(comm, kev):
    if comm and (comm.content or {}).get("references"):
        return comm.content["references"]
    return [{"label": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{kev.cve_id}"},
            {"label": "CISA KEV", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}]


def build(db, uc: UseCase):
    """Devuelve (asunto, texto, html, adjuntos) del mail del SOC para el caso."""
    alert = db.get(Alert, uc.alert_id)
    kev = db.get(KevVulnerability, alert.cve_id)
    enr = db.get(CveEnrichment, alert.cve_id)
    comm = db.scalar(select(Communication).where(Communication.alert_id == alert.id))
    fg = (comm.content or {}).get("fortiguard") if comm else None
    cfg = get_settings(db)
    url = f"{cfg['public_url']}/casos-de-uso/{uc.code}"
    fl = flow(db, uc, alert)
    sev = fl["severity"]
    attack = attack_flow(kev, enr, fg)
    rb = runbook(kev, enr, fg, alert, _refs(comm, kev))
    name = ((comm.content or {}).get("title") if comm else None) or kev.vulnerability_name
    product = f"{kev.vendor_project} {kev.product}"
    steps = []
    for s in fl["steps"]:
        if s["id"] == "deteccion":
            continue
        if s.get("kind") == "decision":
            s = {**s, "owner": "Decisión del analista",
                 "actions": [f"Sí → {s.get('si_label', '')}", f"No → {s.get('no_label', '')}"]}
        steps.append(s)
    deadlines = [(s["title"], _when(s["due"]["at"])) for s in steps if s.get("due")]
    comm_line = ""
    if comm and comm.status == "programado" and comm.scheduled_at:
        comm_line = f"El aviso a clientes ({comm.code}) sale automáticamente a las {comm.scheduled_at.astimezone(TZ):%H:%M} hs."
    elif comm:
        comm_line = f"Comunicado a clientes: {comm.code} ({comm.status})."

    subject = f"[SOC · {sev}] {uc.code} · {alert.cve_id} · {product} — playbook de respuesta"

    # ---------- texto plano ----------
    t = [f"{uc.code} · {name}", f"{alert.cve_id} · {product} · puntaje {alert.score}/100 · severidad {sev}", ""]
    if comm_line:
        t += [comm_line, ""]
    if deadlines:
        t.append("PLAZOS")
        t += [f"  - {a}: hasta {b}" for a, b in deadlines] + [""]
    t.append("QUÉ HACER")
    for i, s in enumerate(steps, 1):
        t.append(f"{i}. {s['title']}" + (f" — {s['owner']}" if s.get("owner") else "") + (f" (plazo {s['sla']})" if s.get("sla") else ""))
        t += [f"      · {a[1:].strip()}" if a.startswith("•") else f"   - {a}" for a in s.get("actions") or []]
    t += ["", "CHECKLIST DEL PLAYBOOK"]
    for sec in uc.playbook or []:
        t.append(sec["title"])
        t += [f"   [{'x' if st.get('done') else ' '}] {st['text']}" for st in sec["steps"]]
    t += ["", "Runbook técnico completo adjunto (consultas por SIEM, firewall y EDR).", f"Caso en la consola: {url}"]
    text = "\n".join(t)

    # ---------- HTML (tablas e estilos en línea para clientes de correo) ----------
    e = escape
    h = []
    h.append(f'''<!DOCTYPE html><html lang="es"><body style="margin:0;padding:0;background:#eef2f8;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#eef2f8;padding:24px 10px;">
<tr><td align="center">
<table role="presentation" width="680" cellpadding="0" cellspacing="0" style="max-width:680px;width:100%;background:#ffffff;border-radius:12px;overflow:hidden;font-family:Arial,Helvetica,sans-serif;color:#1e293b;">
<tr><td style="height:4px;background:#1d4ed8;"></td></tr>
<tr><td style="padding:22px 28px 6px;">
  <div style="font:700 11px 'Courier New',monospace;letter-spacing:.14em;color:#64748b;">VECTUS SAT · PLAYBOOK PARA EL EQUIPO SOC · USO INTERNO</div>
  <div style="font:800 21px Arial,sans-serif;color:#0b1b33;margin-top:8px;line-height:1.3;">{e(name)}</div>
  <div style="margin-top:10px;">
    <span style="display:inline-block;background:{SEV_COLOR.get(sev, '#334155')};color:#fff;font:700 11px Arial;padding:4px 9px;border-radius:5px;">SEVERIDAD {e(sev.upper())}</span>
    <span style="display:inline-block;background:#e0e7ff;color:#1e3a8a;font:700 11px 'Courier New',monospace;padding:4px 9px;border-radius:5px;">{e(uc.code)}</span>
    <span style="display:inline-block;background:#f1f5f9;color:#334155;font:700 11px 'Courier New',monospace;padding:4px 9px;border-radius:5px;">{e(alert.cve_id)}</span>
    <span style="display:inline-block;background:#f1f5f9;color:#334155;font:700 11px 'Courier New',monospace;padding:4px 9px;border-radius:5px;">PUNTAJE {alert.score}/100</span>
  </div>
  <div style="font-size:13px;color:#475569;margin-top:10px;">{e(product)}{(' · ' + e(comm_line)) if comm_line else ''}</div>
</td></tr>''')

    if deadlines:
        rows = "".join(f'<tr><td style="padding:6px 10px;border-top:1px solid #fde68a;font-size:13px;">{e(a)}</td>'
                       f'<td style="padding:6px 10px;border-top:1px solid #fde68a;font:700 13px \'Courier New\',monospace;white-space:nowrap;text-align:right;">{e(b)}</td></tr>'
                       for a, b in deadlines)
        h.append(f'''<tr><td style="padding:14px 28px 4px;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#fffbeb;border:1px solid #fcd34d;border-radius:10px;">
  <tr><td colspan="2" style="padding:10px 10px 6px;font:700 12px Arial;color:#92400e;letter-spacing:.06em;">⏱ PLAZOS (DESDE LA DETECCIÓN)</td></tr>{rows}</table>
</td></tr>''')

    h.append('<tr><td style="padding:18px 28px 4px;font:800 15px Arial;color:#0b1b33;">Qué hacer, paso a paso</td></tr>')
    for i, s in enumerate(steps, 1):
        acts = "".join(
            f'<li style="margin:2px 0 2px 14px;list-style:circle;">{e(a[1:].strip())}</li>' if a.startswith("•")
            else f'<li style="margin:3px 0;">{e(a)}</li>' for a in s.get("actions") or [])
        if s.get("detail"):
            acts += f'<li style="margin:3px 0;color:#64748b;">{e(s["detail"])}</li>'
        plazo = f' · plazo {e(s["sla"])}' if s.get("sla") else ""
        owner = (s.get("owner") or "Decisión").upper() + plazo.upper()
        h.append(f'''<tr><td style="padding:8px 28px;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e2e8f0;border-radius:10px;">
  <tr><td style="padding:12px 14px 4px;">
    <span style="display:inline-block;width:22px;height:22px;line-height:22px;text-align:center;border-radius:11px;background:#1d4ed8;color:#fff;font:700 12px Arial;">{i}</span>
    <span style="font:700 14px Arial;color:#0b1b33;margin-left:6px;">{e(s["title"])}</span>
    <div style="margin:6px 0 0 30px;"><span style="display:inline-block;background:{OWNER_BG};color:#1e3a8a;font:700 10.5px 'Courier New',monospace;padding:3px 7px;border-radius:4px;">{e(owner)}</span></div>
  </td></tr>
  <tr><td style="padding:2px 14px 12px 44px;font-size:13px;line-height:1.55;color:#334155;"><ul style="margin:4px 0;padding-left:16px;">{acts}</ul></td></tr>
  </table>
</td></tr>''')

    h.append('<tr><td style="padding:18px 28px 4px;font:800 15px Arial;color:#0b1b33;">Checklist del playbook</td></tr>')
    for sec in uc.playbook or []:
        items = "".join(
            f'<tr><td valign="top" style="width:22px;padding:4px 0;font:14px Arial;color:{"#16a34a" if st.get("done") else "#94a3b8"};">{"☑" if st.get("done") else "☐"}</td>'
            f'<td style="padding:4px 0;font-size:13px;line-height:1.5;color:#334155;">{e(st["text"])}'
            + (f'<div style="font-size:12px;color:#64748b;">{e(st["hint"])}</div>' if st.get("hint") else "") + "</td></tr>"
            for st in sec["steps"])
        h.append(f'''<tr><td style="padding:6px 28px;">
  <div style="font:700 13px Arial;color:#1d4ed8;margin-bottom:2px;">{e(sec["title"])}</div>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0">{items}</table>
</td></tr>''')

    stages = attack.get("stages") if isinstance(attack, dict) else attack
    if stages:
        rows = "".join(
            f'<tr><td valign="top" style="padding:7px 8px;border-top:1px solid #e2e8f0;font-size:12.5px;width:48%;">'
            f'<div style="font:700 10.5px \'Courier New\',monospace;color:#b91c1c;">{e(st.get("tactic", ""))} {e(st.get("mitre", ""))}</div>'
            f'<b>{e(st["title"])}</b></td>'
            f'<td valign="top" style="padding:7px 8px;border-top:1px solid #e2e8f0;font-size:12.5px;color:#166534;">✂ {e(st["cut"])}</td></tr>'
            for st in stages)
        h.append(f'''<tr><td style="padding:18px 28px 4px;font:800 15px Arial;color:#0b1b33;">Cómo se explota y dónde cortarlo</td></tr>
<tr><td style="padding:4px 28px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e2e8f0;border-radius:10px;">{rows}</table></td></tr>''')

    h.append(f'''<tr><td style="padding:20px 28px 8px;font-size:13px;color:#334155;line-height:1.6;">
  📎 <b>Runbook técnico completo adjunto</b>: consultas listas para copiar (Splunk, Sentinel, Wazuh, FortiSIEM, QRadar, Elastic, FortiGate, Palo Alto, Check Point, Defender y más), contención, verificación y criterios de cierre.
</td></tr>
<tr><td align="center" style="padding:10px 28px 24px;">
  <a href="{e(url)}" style="display:inline-block;background:#1d4ed8;color:#ffffff;text-decoration:none;font:700 14px Arial;padding:12px 22px;border-radius:8px;">Abrir el caso en la consola</a>
  <div style="font-size:11.5px;color:#64748b;margin-top:8px;">Registrá ahí el avance: pasos del playbook y seguimiento por cliente.</div>
</td></tr>
<tr><td style="padding:12px 28px;background:#f8fafc;border-top:1px solid #e2e8f0;font:11px 'Courier New',monospace;color:#94a3b8;">
  Uso interno del SOC · no reenviar a clientes · Vectus SAT
</td></tr>
</table></td></tr></table></body></html>''')
    html = "\n".join(h)

    md = runbook_markdown(uc.code, f"{product} · {alert.cve_id}", rb)
    attachments = [(f"Runbook {uc.code} {alert.cve_id}.md", md.encode(), "text/markdown")]
    return subject, text, html, attachments


def send(db, uc: UseCase, to: list[str], user_email: str = "sistema") -> None:
    subject, text, html, atts = build(db, uc)
    mailer.send_simple(to, subject, text, html, atts)
    uc.history = list(uc.history or []) + [{"fecha": now_iso(), "evento": "playbook_enviado", "usuario": user_email,
                                            "comentario": "Playbook enviado por mail a " + ", ".join(to)}]


def notify_new_cases() -> list[str]:
    """Worker: envía el playbook al SOC para cada caso nuevo que todavía no se notificó."""
    from app.db import SessionLocal
    from app.auth import now_utc

    sent = []
    with SessionLocal() as db:
        cfg = get_settings(db)
        soc = cfg.get("soc_emails") or []
        if not cfg.get("soc_playbook_mail", True) or not soc or not mailer.is_configured():
            return sent
        for uc in db.scalars(select(UseCase).where(UseCase.soc_notified_at.is_(None), UseCase.status == "abierto")
                             .order_by(UseCase.id)).all():
            try:
                send(db, uc, soc)
                uc.soc_notified_at = now_utc()
                sent.append(uc.code)
            except Exception as exc:  # noqa: BLE001
                log.error("No se pudo enviar el playbook de %s al SOC: %s", uc.code, exc)
                break   # se reintenta en el próximo ciclo
            finally:
                db.commit()
    return sent
