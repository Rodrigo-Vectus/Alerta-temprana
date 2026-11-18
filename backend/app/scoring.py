import argparse
import logging
import os
import re
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert

from app.db import SessionLocal, init_db
from app.enrichment import enrich
from app.models import (Alert, Client, ClientTechnology, CveEnrichment,
                        KevEvent, KevVulnerability, WatchVendor)

log = logging.getLogger("scoring")
ALERT_THRESHOLD = int(os.getenv("ALERT_THRESHOLD", "60"))
MONITOR_THRESHOLD = int(os.getenv("MONITOR_THRESHOLD", "40"))
AUTO_STATUSES = {"candidata", "monitoreo", "descartada_auto"}

DEFAULT_WATCHLIST = {
    1: ["Microsoft", "Fortinet", "Cisco", "VMware", "Broadcom", "Citrix", "Palo Alto Networks",
        "Ivanti", "Check Point", "SonicWall", "Juniper", "F5", "Apache", "PHP", "Atlassian",
        "Oracle", "SAP", "Google", "Apple", "Linux", "Veeam"],
    2: ["Progress", "SolarWinds", "Zimbra", "Adobe", "Mozilla", "QNAP", "Synology", "Zyxel",
        "D-Link", "TP-Link", "Sophos", "WatchGuard", "MikroTik", "GitLab", "Jenkins",
        "WordPress", "Docker", "Kubernetes", "Grafana", "Elastic", "Red Hat", "Samsung", "Android"],
}

CRITICAL_CWES = {
    "CWE-78": "Inyección de comandos SO", "CWE-77": "Inyección de comandos", "CWE-94": "Inyección de código",
    "CWE-502": "Deserialización insegura", "CWE-287": "Autenticación incorrecta",
    "CWE-306": "Falta de autenticación", "CWE-288": "Bypass de autenticación", "CWE-22": "Path traversal",
    "CWE-434": "Subida de archivos sin restricción", "CWE-918": "SSRF", "CWE-89": "Inyección SQL",
    "CWE-798": "Credenciales embebidas", "CWE-522": "Credenciales mal protegidas",
    "CWE-787": "Escritura fuera de límites", "CWE-416": "Use-after-free", "CWE-269": "Gestión de privilegios",
}

KEYWORDS = [
    (r"remote code execution|execute arbitrary (code|commands)|arbitrary code execution|code execution",
     "Ejecución remota de código", 15),
    (r"authentication bypass|bypass(es)? (the )?authentication|without authentication", "Bypass de autenticación", 15),
    (r"command injection|os command", "Inyección de comandos", 15),
    (r"ntlm|credential|password hash", "Robo o exposición de credenciales", 12),
    (r"privilege escalation|elevat(e|ion) (of )?privilege", "Escalamiento de privilegios", 8),
]


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _wb(needle, hay):
    """Coincidencia por palabra completa (evita que 'SAP' matchee 'Sapido')."""
    needle, hay = (needle or "").strip().lower(), (hay or "").lower()
    return bool(needle) and re.search(rf"(?<![a-z0-9]){re.escape(needle)}(?![a-z0-9])", hay) is not None


def seed_watchlist(db):
    if db.scalar(select(func.count()).select_from(WatchVendor)):
        return
    rows = [{"vendor": v, "tier": t} for t, vs in DEFAULT_WATCHLIST.items() for v in vs]
    db.execute(insert(WatchVendor).values(rows).on_conflict_do_nothing(index_elements=["vendor"]))
    db.commit()


def load_watch(db):
    return {w.vendor: w.tier for w in db.scalars(select(WatchVendor)).all()}


def watch_tier(kev, watch):
    tiers = [t for v, t in watch.items() if _wb(v, kev.vendor_project) or _wb(v, kev.product)]
    return min(tiers) if tiers else None


def load_techs(db):
    q = (select(ClientTechnology, Client.name)
         .join(Client, Client.id == ClientTechnology.client_id)
         .where(Client.active.is_(True)))
    return db.execute(q).all()


def match_clients(kev, techs):
    out = []
    for tech, cname in techs:
        if not (_wb(tech.vendor, kev.vendor_project) or _wb(kev.vendor_project, tech.vendor)):
            continue
        tp, kp = (tech.product or "").strip(), kev.product or ""
        if tp in ("", "*") or kp.lower() == "multiple products" or _wb(tp, kp) or _wb(kp, tp):
            out.append({"client_id": tech.client_id, "client": cname, "vendor": tech.vendor,
                        "product": tp or "*", "version": tech.version,
                        "internet_exposed": tech.internet_exposed})
    return out


def compute(kev, enr, tier, matches):
    bd = []

    def add(factor, pts, detalle):
        bd.append({"factor": factor, "puntos": pts, "detalle": detalle})

    add("Explotación activa (CISA KEV)", 20, f"Agregada al catálogo el {kev.date_added}")
    if tier == 1:
        add("Fabricante de uso masivo", 20, kev.vendor_project)
    elif tier == 2:
        add("Fabricante vigilado", 10, kev.vendor_project)

    if matches:
        add("Tecnología presente en clientes", 25, ", ".join(sorted({m["client"] for m in matches})))
        exposed = sorted({m["client"] for m in matches if m["internet_exposed"]})
        if exposed:
            add("Expuesta a internet en clientes", 5, ", ".join(exposed))

    text = f"{kev.vulnerability_name} {kev.short_description}".lower()
    best = None
    for pat, label, pts in KEYWORDS:
        if re.search(pat, text) and (best is None or pts > best[1]):
            best = (label, pts)
    cwes = set(kev.cwes or []) | set((enr.cwes if enr else None) or [])
    crit = [f"{c} ({CRITICAL_CWES[c]})" for c in sorted(cwes) if c in CRITICAL_CWES]
    if best:
        add("Tipo de falla", best[1], best[0])
    elif crit:
        add("Tipo de falla", 10, ", ".join(crit))

    if (kev.known_ransomware or "").lower() == "known":
        add("Usada en campañas de ransomware", 10, "CISA: Known")

    if enr and enr.epss is not None:
        if enr.epss >= 0.5:
            add("EPSS alto", 10, f"{enr.epss:.2%}")
        elif enr.epss >= 0.1:
            add("EPSS medio", 5, f"{enr.epss:.2%}")

    if enr and enr.cvss_score is not None:
        if enr.cvss_score >= 9:
            add("CVSS crítico", 10, f"{enr.cvss_score} (v{enr.cvss_version})")
        elif enr.cvss_score >= 7:
            add("CVSS alto", 5, f"{enr.cvss_score} (v{enr.cvss_version})")

    vec = (enr.cvss_vector or "") if enr else ""
    if "AV:N" in vec and "PR:N" in vec:
        add("Explotable por red sin autenticación", 5, vec)

    if kev.date_added and kev.due_date and (kev.due_date - kev.date_added).days <= 7:
        add("Plazo de CISA urgente", 5, f"{(kev.due_date - kev.date_added).days} días")

    return min(100, sum(b["puntos"] for b in bd)), bd


def classify(score):
    if score >= ALERT_THRESHOLD:
        return "alta", "candidata"
    if score >= MONITOR_THRESHOLD:
        return "media", "monitoreo"
    return "baja", "descartada_auto"


def evaluate(db, cid, watch, techs, trigger):
    kev = db.get(KevVulnerability, cid)
    if not kev:
        return None
    enr = db.get(CveEnrichment, cid)
    matches = match_clients(kev, techs)
    score, bd = compute(kev, enr, watch_tier(kev, watch), matches)
    level, status = classify(score)
    alert = db.scalar(select(Alert).where(Alert.cve_id == cid))
    entry = {"fecha": _now_iso(), "evento": trigger, "score": score}

    if alert is None:
        prev = None
        alert = Alert(cve_id=cid, score=score, level=level, status=status, breakdown=bd,
                      matched_clients=matches, history=[entry])
        db.add(alert)
        db.flush()
        alert.code = f"SAT-{date.today().year}-{alert.id:04d}"
    else:
        prev = alert.score
        alert.score, alert.level, alert.breakdown, alert.matched_clients = score, level, bd, matches
        if alert.status in AUTO_STATUSES:
            alert.status = status
        if prev != score or trigger in ("nueva_en_kev", "actualizada_en_kev"):
            entry["score_anterior"] = prev
            alert.history = list(alert.history or []) + [entry]

    if alert.status == "candidata" and (prev is None or prev < ALERT_THRESHOLD):
        log.warning("ALERTA CANDIDATA %s | %s | %s %s | score %s",
                    alert.code, cid, kev.vendor_project, kev.product, score)
    return alert


def process_pending(limit=50):
    with SessionLocal() as db:
        events = db.scalars(select(KevEvent).where(KevEvent.processed.is_(False))
                            .order_by(KevEvent.id).limit(limit)).all()
        if not events:
            return {"processed": 0}
        triggers = {e.cve_id: ("nueva_en_kev" if e.event_type == "new" else "actualizada_en_kev")
                    for e in events}
        cves = sorted(triggers)
        enrich(db, cves)
        watch, techs = load_watch(db), load_techs(db)
        out = []
        for cid in cves:
            a = evaluate(db, cid, watch, techs, triggers[cid])
            if a:
                out.append({"code": a.code, "cve": cid, "score": a.score, "status": a.status, "trigger": triggers[cid]})
        for e in events:
            e.processed = True
        db.commit()
        return {"processed": len(events), "alerts": out}


def refresh_incomplete(max_items=10):
    """Reintenta NVD para alertas recientes que quedaron sin datos (NVD suele demorar)."""
    with SessionLocal() as db:
        since = datetime.now(timezone.utc) - timedelta(days=7)
        q = (select(Alert.cve_id)
             .join(CveEnrichment, CveEnrichment.cve_id == Alert.cve_id, isouter=True)
             .where(Alert.status.in_(AUTO_STATUSES), Alert.created_at >= since,
                    (CveEnrichment.nvd_ok.is_(False)) | (CveEnrichment.cve_id.is_(None)))
             .limit(max_items))
        cves = list(db.scalars(q).all())
        if not cves:
            return {"refreshed": 0}
        enrich(db, cves, max_age_hours=0)
        watch, techs = load_watch(db), load_techs(db)
        for cid in cves:
            evaluate(db, cid, watch, techs, "reintento_nvd")
        db.commit()
        return {"refreshed": len(cves)}


def rescore_all():
    """Recalcula todas las alertas (ej. después de cambiar el inventario de clientes)."""
    with SessionLocal() as db:
        watch, techs = load_watch(db), load_techs(db)
        before = dict(db.execute(select(Alert.cve_id, Alert.score)).all())
        changed = 0
        for cid, old in before.items():
            a = evaluate(db, cid, watch, techs, "recalculo")
            if a and a.score != old:
                changed += 1
        db.commit()
        return {"total": len(before), "changed": changed}


def preview(days):
    """Muestra qué puntaje tendrían las KEV de los últimos N días, sin crear alertas."""
    with SessionLocal() as db:
        since = date.today() - timedelta(days=days)
        kevs = db.scalars(select(KevVulnerability).where(KevVulnerability.date_added >= since)
                          .order_by(KevVulnerability.date_added.desc())).all()
        print(f"{len(kevs)} KEV en los últimos {days} días. Consultando NVD/EPSS...")
        enrich(db, [k.cve_id for k in kevs])
        watch, techs = load_watch(db), load_techs(db)
        rows = []
        for k in kevs:
            enr = db.get(CveEnrichment, k.cve_id)
            s, _ = compute(k, enr, watch_tier(k, watch), match_clients(k, techs))
            rows.append((s, classify(s)[1], k.cve_id, str(k.date_added),
                         enr.cvss_score if enr else None, enr.epss if enr else None,
                         f"{k.vendor_project} {k.product}"[:45]))
        rows.sort(key=lambda r: r[0], reverse=True)
        print(f"{'SCORE':>5}  {'ESTADO':<16} {'CVE':<18} {'FECHA':<10} {'CVSS':>5} {'EPSS':>6}  PRODUCTO")
        for s, st, cve, d, cv, ep, prod in rows:
            print(f"{s:>5}  {st:<16} {cve:<18} {d:<10} {cv if cv is not None else '-':>5} "
                  f"{(f'{ep:.3f}' if ep is not None else '-'):>6}  {prod}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [scoring] %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    p = argparse.ArgumentParser()
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--process", action="store_true", help="Procesar eventos pendientes")
    g.add_argument("--rescore-all", action="store_true", help="Recalcular todas las alertas")
    g.add_argument("--preview", type=int, metavar="DIAS", help="Simular puntaje de KEV recientes")
    a = p.parse_args()
    init_db()
    with SessionLocal() as db:
        seed_watchlist(db)
    if a.process:
        print(process_pending())
    elif a.rescore_all:
        print(rescore_all())
    else:
        preview(a.preview)
