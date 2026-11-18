import argparse
import hashlib
import json
import logging
import os
from datetime import date, datetime, timezone

import httpx
from sqlalchemy import select

from app.db import SessionLocal, init_db
from app.models import CollectorRun, KevEvent, KevVulnerability

KEV_URL = os.getenv(
    "KEV_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)
TRACKED = [
    "vendorProject", "product", "vulnerabilityName", "shortDescription",
    "requiredAction", "notes", "knownRansomwareCampaignUse", "cwes",
    "dateAdded", "dueDate",
]
log = logging.getLogger("kev")


def _now():
    return datetime.now(timezone.utc)


def _date(value):
    try:
        return date.fromisoformat(value) if value else None
    except ValueError:
        return None


def _hash(item):
    payload = {k: item.get(k) for k in TRACKED}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _fields(item):
    return dict(
        vendor_project=item.get("vendorProject", ""),
        product=item.get("product", ""),
        vulnerability_name=item.get("vulnerabilityName", ""),
        short_description=item.get("shortDescription", ""),
        required_action=item.get("requiredAction"),
        notes=item.get("notes"),
        known_ransomware=item.get("knownRansomwareCampaignUse"),
        cwes=item.get("cwes") or [],
        date_added=_date(item.get("dateAdded")),
        due_date=_date(item.get("dueDate")),
    )


def fetch_catalog():
    headers = {"User-Agent": "Vectus-SAT/0.1 (+https://www.vectus.la)"}
    with httpx.Client(timeout=60, follow_redirects=True, headers=headers) as client:
        resp = client.get(KEV_URL)
        resp.raise_for_status()
        return resp.json()


def run_once(force: bool = False) -> dict:
    db = SessionLocal()
    run = CollectorRun(source="cisa_kev", status="running")
    db.add(run)
    db.commit()
    run_id = run.id
    try:
        data = fetch_catalog()
        version = data.get("catalogVersion")
        items = data.get("vulnerabilities", [])
        run.catalog_version, run.total = version, len(items)

        last_ok = db.scalar(
            select(CollectorRun)
            .where(CollectorRun.source == "cisa_kev",
                   CollectorRun.status.in_(["ok", "baseline", "unchanged"]),
                   CollectorRun.id != run_id)
            .order_by(CollectorRun.id.desc()).limit(1)
        )
        if not force and last_ok and last_ok.catalog_version == version:
            run.status, run.finished_at = "unchanged", _now()
            db.commit()
            return {"status": "unchanged", "catalog_version": version, "total": len(items)}

        existing = dict(db.execute(select(KevVulnerability.cve_id, KevVulnerability.content_hash)).all())
        baseline = len(existing) == 0
        new_count = updated_count = 0

        for item in items:
            cve = item.get("cveID")
            if not cve:
                continue
            h = _hash(item)

            if cve not in existing:
                db.add(KevVulnerability(cve_id=cve, content_hash=h, raw=item, **_fields(item)))
                new_count += 1
                if not baseline:
                    db.flush()
                    db.add(KevEvent(cve_id=cve, event_type="new", changed_fields={}))
                    log.warning("NUEVA en KEV: %s | %s %s", cve, item.get("vendorProject"), item.get("product"))

            elif existing[cve] != h:
                row = db.get(KevVulnerability, cve)
                changed = {
                    k: {"antes": row.raw.get(k), "ahora": item.get(k)}
                    for k in TRACKED if row.raw.get(k) != item.get(k)
                }
                for attr, value in _fields(item).items():
                    setattr(row, attr, value)
                row.content_hash, row.raw = h, item
                row.change_count = (row.change_count or 0) + 1
                row.last_changed_at = _now()
                db.add(KevEvent(cve_id=cve, event_type="updated", changed_fields=changed))
                updated_count += 1
                log.warning("ACTUALIZADA en KEV: %s | campos: %s", cve, list(changed))

        run.status = "baseline" if baseline else "ok"
        run.new_count, run.updated_count, run.finished_at = new_count, updated_count, _now()
        db.commit()
        return {"status": run.status, "catalog_version": version, "total": len(items),
                "new": new_count, "updated": updated_count}

    except Exception as exc:
        db.rollback()
        run = db.get(CollectorRun, run_id)
        run.status, run.error, run.finished_at = "error", str(exc)[:2000], _now()
        db.commit()
        log.exception("Error en recolector KEV")
        return {"status": "error", "error": str(exc)}
    finally:
        db.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [kev] %(levelname)s %(message)s")
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true", help="Procesar aunque catalogVersion no haya cambiado")
    args = parser.parse_args()
    init_db()
    print(json.dumps(run_once(force=args.force), indent=2, ensure_ascii=False))
