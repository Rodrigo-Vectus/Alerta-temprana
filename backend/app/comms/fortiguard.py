"""Cobertura de FortiGuard para una CVE (firmas IPS, Outbreak Alerts, detección en endpoints, antivirus…).

Se lee la página pública de búsqueda de FortiGuard, que trae los resultados en el HTML. Las páginas de
detalle de cada firma están detrás de Cloudflare, así que no se consultan: alcanza con la búsqueda.
Si FortiGuard no responde o cambia su formato, devuelve None y el comunicado usa el texto genérico.
"""
import html
import logging
import re

import httpx

log = logging.getLogger("fortiguard")
BASE = "https://www.fortiguard.com"
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36",
      "Accept-Language": "en-US,en;q=0.9"}

# Tipo que muestra FortiGuard -> clave interna
TYPES = {
    "outbreak alert": "outbreak", "ips": "ips", "endpoint vulnerability": "endpoint",
    "virus": "virus", "dynamic application security testing": "dast", "web application firewall": "waf",
    "waf": "waf", "application": "app", "botnet c&c": "botnet", "threat signal": "signal",
}


def _clean(s: str) -> str:
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", s or ""))).strip()


def parse(page: str, cve: str) -> dict:
    links = dict(re.findall(r"getElementById\('fwb_id_(\d+)'\).*?location\.href\s*=\s*'([^']+)'", page))
    blocks = re.split(r'id="fwb_id_(\d+)">', page)
    items = []
    for i in range(1, len(blocks) - 1, 2):
        n, body = blocks[i], blocks[i + 1][:4000]
        kind = _clean((re.search(r"<small>(.*?)</small>", body, re.S) or [None, ""])[1])
        name = _clean((re.search(r"<br>\s*<b>(.*?)</b>", body, re.S) or [None, ""])[1])
        cves = sorted(set(re.findall(r'data-cveid="(CVE-\d{4}-\d+)"', body)))
        cols = re.findall(r'<div class="col-md-5">\s*<small>(.*?)</small>', body, re.S)
        tags = [_clean(t) for t in re.findall(r'class="tag-pill[^"]*"[^>]*>(.*?)</a>', body, re.S)]
        if not name:
            continue
        items.append({"type": TYPES.get(kind.lower(), kind.lower()), "kind": kind, "name": name, "cves": cves,
                      "summary": _clean(cols[0]) if cols else "", "tags": tags,
                      "url": BASE + links[n] if n in links else None, "id": (links.get(n, "").rstrip("/").split("/") or [""])[-1]})

    outbreaks = [x for x in items if x["type"] == "outbreak" and cve in x["cves"]]
    campaigns = {o["name"] for o in outbreaks}
    direct = [x for x in items if cve in x["cves"]]
    # Firmas sin CVE propia (ej. antivirus) que FortiGuard asocia a la misma campaña
    related = [x for x in items if not x["cves"] and campaigns & set(x["tags"])]
    out = {"cve": cve, "search_url": f"{BASE}/search?q={cve}&engine=1"}
    for key in ("ips", "endpoint", "dast", "waf", "app", "signal"):
        out[key] = [x for x in direct if x["type"] == key]
    out["outbreak"] = outbreaks[0] if outbreaks else None
    out["virus"] = [x for x in direct + related if x["type"] == "virus"]
    out["found"] = any(out[k] for k in ("ips", "endpoint", "dast", "waf", "app", "virus")) or bool(out["outbreak"])
    return out


def lookup(cve: str, client: httpx.Client | None = None) -> dict | None:
    try:
        c = client or httpx.Client(timeout=20, follow_redirects=True, headers=UA)
        r = c.get(f"{BASE}/search", params={"q": cve, "engine": "1"})
        if r.status_code != 200 or "fwb_id_" not in r.text:
            log.info("FortiGuard sin resultados para %s (HTTP %s)", cve, r.status_code)
            return None
        data = parse(r.text, cve)
        log.info("FortiGuard %s: ips=%s endpoint=%s virus=%s outbreak=%s", cve, len(data["ips"]),
                 len(data["endpoint"]), len(data["virus"]), bool(data["outbreak"]))
        return data if data["found"] else None
    except Exception as exc:
        log.warning("No se pudo consultar FortiGuard para %s: %s", cve, exc)
        return None
