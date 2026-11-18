import logging
import os
import time
from datetime import datetime, timezone

import httpx

from app.models import CveEnrichment

log = logging.getLogger("enrichment")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
NVD_DELAY = 0.7 if NVD_API_KEY else 6.5
UA = {"User-Agent": "Vectus-SAT/0.3 (+https://www.vectus.la)"}
_last_nvd = 0.0


def _nvd_wait():
    global _last_nvd
    wait = NVD_DELAY - (time.monotonic() - _last_nvd)
    if wait > 0:
        time.sleep(wait)
    _last_nvd = time.monotonic()


def fetch_nvd(cve_id):
    headers = dict(UA)
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    for attempt in range(3):
        _nvd_wait()
        try:
            r = httpx.get(NVD_URL, params={"cveId": cve_id}, headers=headers, timeout=30)
            if r.status_code in (403, 429, 503):
                log.warning("NVD %s para %s, reintento %s", r.status_code, cve_id, attempt + 1)
                time.sleep(10 * (attempt + 1))
                continue
            r.raise_for_status()
            vulns = r.json().get("vulnerabilities", [])
            return vulns[0]["cve"] if vulns else None
        except httpx.HTTPError as exc:
            log.warning("NVD error %s: %s", cve_id, exc)
            time.sleep(5)
    return None


def parse_nvd(cve):
    out = {}
    metrics = cve.get("metrics", {})
    for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV40", "4.0"),
                     ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        lst = metrics.get(key)
        if lst:
            m = next((x for x in lst if x.get("type") == "Primary"), lst[0])
            d = m.get("cvssData", {})
            out.update(cvss_score=d.get("baseScore"), cvss_version=ver,
                       cvss_severity=d.get("baseSeverity") or m.get("baseSeverity"),
                       cvss_vector=d.get("vectorString"))
            break
    cwes = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in cwes:
                cwes.append(v)
    cpes = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                c = m.get("criteria")
                if m.get("vulnerable") and c and c not in cpes:
                    cpes.append(c)
    pub = cve.get("published")
    published = None
    if pub:
        published = datetime.fromisoformat(pub)
        if published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)
    out.update(cwes=cwes, cpes=cpes[:200], nvd_status=cve.get("vulnStatus"), nvd_published=published,
               ref_urls=[r.get("url") for r in cve.get("references", []) if r.get("url")][:30])
    return out


def fetch_epss(cve_ids):
    res = {}
    for i in range(0, len(cve_ids), 50):
        chunk = cve_ids[i:i + 50]
        try:
            r = httpx.get(EPSS_URL, params={"cve": ",".join(chunk)}, headers=UA, timeout=30)
            r.raise_for_status()
            for d in r.json().get("data", []):
                res[d["cve"]] = (float(d["epss"]), float(d["percentile"]))
        except Exception as exc:
            log.warning("EPSS error: %s", exc)
    return res


def enrich(db, cve_ids, max_age_hours=24):
    if not cve_ids:
        return
    epss = fetch_epss(list(cve_ids))
    now = datetime.now(timezone.utc)
    for cid in cve_ids:
        row = db.get(CveEnrichment, cid)
        fresh = bool(row and row.nvd_ok and row.fetched_at
                     and (now - row.fetched_at).total_seconds() < max_age_hours * 3600)
        if row is None:
            row = CveEnrichment(cve_id=cid)
            db.add(row)
        if not fresh:
            cve = fetch_nvd(cid)
            if cve:
                for k, v in parse_nvd(cve).items():
                    setattr(row, k, v)
                row.nvd_ok = True
            else:
                log.info("NVD sin datos aún para %s", cid)
        if cid in epss:
            row.epss, row.epss_percentile = epss[cid]
            row.epss_ok = True
        row.fetched_at = now
        db.commit()
