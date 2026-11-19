"""Generación del contenido de un comunicado a partir de datos públicos (CISA KEV + NVD + EPSS).

Todo el texto se arma con plantillas en español. El resultado es un dict editable por el
analista desde la consola; el newsletter y el informe se renderizan a partir de ese dict.
"""
import re
from datetime import date

MONTHS = ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto",
          "septiembre", "octubre", "noviembre", "diciembre"]
SEVERITY_ES = {"CRITICAL": "crítica", "HIGH": "alta", "MEDIUM": "media", "LOW": "baja"}

# (patrón sobre el nombre/descripción, descripción de la falla, etiqueta para el título, género, familia)
TYPES = [
    (r"ntlm|hash disclosure", "filtración de credenciales (hash NTLM)", "Filtración de credenciales", "f", "creds"),
    (r"os command injection|command injection", "inyección de comandos del sistema operativo", "Inyección de comandos", "f", "rce"),
    (r"code injection", "inyección de código", "Inyección de código", "f", "rce"),
    (r"remote code execution", "ejecución remota de código", "Ejecución remota de código", "f", "rce"),
    (r"deserialization", "deserialización de datos no confiables", "Deserialización insegura", "f", "rce"),
    (r"sql injection", "inyección SQL", "Inyección SQL", "f", "rce"),
    (r"unrestricted upload", "carga de archivos sin restricción", "Carga arbitraria de archivos", "f", "rce"),
    (r"authentication bypass|improper authentication|missing authentication|bypass", "omisión de autenticación", "Bypass de autenticación", "m", "auth"),
    (r"hard-?coded (credential|password)", "credenciales embebidas en el producto", "Falla de credenciales embebidas", "f", "auth"),
    (r"missing authorization|incorrect authorization|improper access control|incorrect permission|improper privilege", "control de acceso o asignación de permisos incorrecta", "Falla de control de acceso", "f", "auth"),
    (r"server-side request forgery|ssrf", "falsificación de solicitudes del lado del servidor (SSRF)", "Vulnerabilidad SSRF", "f", "web"),
    (r"cross-site scripting|xss", "cross-site scripting (XSS)", "Vulnerabilidad XSS", "f", "web"),
    (r"path traversal|directory traversal", "recorrido de directorios (path traversal)", "Path traversal", "m", "web"),
    (r"use-after-free|use after free", "uso de memoria liberada (use-after-free)", "Corrupción de memoria", "f", "mem"),
    (r"out-of-bounds|buffer overflow|heap-based|stack-based|memory corruption|type confusion|integer overflow",
     "corrupción de memoria", "Corrupción de memoria", "f", "mem"),
    (r"privilege escalation|elevation of privilege", "escalamiento de privilegios", "Escalamiento de privilegios", "m", "priv"),
    (r"information disclosure|exposure of sensitive|sensitive information", "exposición de información sensible", "Exposición de información sensible", "f", "creds"),
    (r"input validation", "validación incorrecta de datos de entrada", "Falla de validación de entrada", "f", "other"),
    (r"denial of service", "denegación de servicio", "Denegación de servicio", "f", "dos"),
]

SURFACES = [
    ("perimetral", r"fortios|fortigate|fortiweb|fortimanager|fortiproxy|pan-os|palo alto|check point|adaptive security|asa|firepower|ivanti|pulse|connect secure|citrix|netscaler|sonicwall|juniper|junos|big-ip|f5|zyxel|watchguard|mikrotik|d-link|tp-link|vpn|firewall|router|gateway"),
    ("correo", r"outlook|exchange|office|word|excel|powerpoint|zimbra|roundcube|mail"),
    ("virtualizacion", r"vmware|esxi|vcenter|veeam|hyper-v|backup|proxmox|nutanix"),
    ("navegador", r"chrome|chromium|firefox|safari|webkit|edge|browser"),
    ("web", r"php|apache|tomcat|struts|wordpress|drupal|joomla|confluence|jira|atlassian|gitlab|jenkins|nginx|iis|sharepoint|moveit|laravel|craft|web|http|portal"),
    ("so", r"windows|linux|kernel|macos|ios|android|server"),
]

IMPACT_SENTENCE = {
    "rce": "Un atacante puede aprovecharla para ejecutar código en el sistema afectado y tomar control de él.",
    "auth": "Permite a un atacante acceder a funciones o datos protegidos sin credenciales válidas.",
    "creds": "Permite a un atacante obtener credenciales o información sensible para suplantar a los usuarios.",
    "priv": "Permite a un atacante con acceso limitado obtener privilegios elevados sobre el sistema.",
    "mem": "Puede aprovecharse para ejecutar código malicioso o provocar la caída del servicio.",
    "web": "Permite a un atacante abusar de la aplicación web para acceder a información o recursos internos.",
    "dos": "Permite a un atacante interrumpir la disponibilidad del servicio.",
    "other": "Ya está siendo aprovechada por atacantes en ataques reales.",
}

SURFACE_ACTION = {
    "perimetral": "Hasta actualizar, restringir el acceso a la interfaz de administración y a los servicios publicados (VPN, portal web) solo desde direcciones IP de confianza.",
    "correo": "Hasta parchear, alertar a los usuarios: no abrir adjuntos ni enlaces de remitentes desconocidos o inesperados.",
    "web": "Si el servicio está publicado en internet, protegerlo detrás de un WAF y limitar el acceso hasta aplicar el parche.",
    "virtualizacion": "Aislar las interfaces de administración en una red de gestión dedicada y verificar que existan copias de seguridad recientes fuera de línea.",
    "navegador": "Forzar la actualización de los navegadores en todos los equipos y reiniciarlos para que el parche quede activo.",
    "so": "Priorizar el despliegue del parche en servidores críticos y equipos expuestos a internet.",
    "general": "Si no es posible actualizar de inmediato, aplicar las mitigaciones indicadas por el fabricante o aislar el sistema afectado.",
}

FAMILY_ACTION = {
    "creds": "Revisar eventos de autenticación anómalos y rotar las credenciales que puedan haberse expuesto.",
    "auth": "Revisar accesos administrativos recientes y cuentas creadas o modificadas sin autorización.",
    "priv": "Revisar cuentas con privilegios elevados y actividad administrativa inusual en los sistemas afectados.",
}
DEFAULT_FAMILY_ACTION = "Revisar registros y alertas de seguridad en busca de procesos, conexiones o archivos inusuales en los sistemas afectados."

HARDENING_BASE = [
    "Mantener un proceso de gestión de parches que priorice las vulnerabilidades incluidas en el catálogo KEV de CISA.",
    "Exigir autenticación multifactor (MFA) en accesos remotos, VPN y cuentas privilegiadas.",
    "Aplicar el principio de mínimo privilegio y revisar periódicamente las cuentas administrativas.",
    "Segmentar la red y restringir las interfaces de administración a una red de gestión dedicada.",
    "Deshabilitar servicios, puertos y funcionalidades que no se utilicen.",
    "Mantener copias de seguridad periódicas, cifradas y fuera de línea, y probar su restauración.",
    "Centralizar los registros de seguridad y conservarlos al menos 90 días para análisis forense.",
]
HARDENING_SURFACE = {
    "perimetral": ["No exponer la interfaz de administración de firewalls y VPN a internet.",
                   "Revisar la configuración tras actualizar: cuentas locales, reglas y certificados."],
    "correo": ["Configurar SPF, DKIM y DMARC, y bloquear tipos de adjuntos de riesgo.",
               "Bloquear el tráfico SMB/NTLM saliente hacia internet (puerto TCP 445)."],
    "web": ["Publicar las aplicaciones detrás de un WAF y ejecutar los servicios con usuarios sin privilegios.",
            "Eliminar módulos, plugins y componentes innecesarios del servidor web."],
    "virtualizacion": ["Separar las credenciales de administración de la virtualización del dominio corporativo.",
                       "Mantener copias de seguridad inmutables de máquinas virtuales críticas."],
    "navegador": ["Gestionar los navegadores de forma centralizada y restringir extensiones no autorizadas."],
    "so": ["Aplicar las líneas base de configuración segura (CIS Benchmarks) en servidores y estaciones."],
    "general": [],
}

NEXT_STEPS = ("Vectus SA queda a disposición para apoyar en la evaluación de la exposición específica de su entorno, "
              "la verificación de versiones afectadas, la activación de controles compensatorios con la suite Fortinet "
              "y la revisión de registros en busca de indicadores de compromiso. Recomendamos realizar una breve reunión "
              "de seguimiento una vez aplicadas las actualizaciones, para validar el estado de la seguridad y las lecciones aprendidas.")


def fecha_larga(d):
    if not d:
        return "—"
    if isinstance(d, str):
        d = date.fromisoformat(d[:10])
    return f"{d.day} de {MONTHS[d.month - 1]} de {d.year}"


def fecha_corta(d):
    if not d:
        return "—"
    if isinstance(d, str):
        d = date.fromisoformat(d[:10])
    return d.strftime("%d/%m/%Y")


def product_display(vendor: str, product: str) -> str:
    vendor, product = (vendor or "").strip(), (product or "").strip()
    if product.lower() == "multiple products":
        return f"múltiples productos de {vendor}"
    if not product:
        return vendor
    first = vendor.split()[0].lower() if vendor else ""
    if first and (product.lower().startswith(first) or first in product.lower().split()):
        return product
    return f"{vendor} {product}"


def product_short(vendor: str, product: str) -> str:
    """Forma corta para usar dentro de oraciones ("los productos Check Point afectados")."""
    if (product or "").strip().lower() == "multiple products":
        return f"los productos {vendor} afectados"
    return product_display(vendor, product)


def classify(kev, enr):
    text = f"{kev.vulnerability_name} {kev.short_description}".lower()
    name = (kev.vulnerability_name or "").lower()
    vtype = next((t for t in TYPES if re.search(t[0], name)), None) or next((t for t in TYPES if re.search(t[0], text)), None)
    if vtype is None:
        vtype = (None, "seguridad", "Vulnerabilidad crítica", "f", "other")
    _, desc, label, gender, family = vtype
    rce_text = re.search(r"remote code execution|execute arbitrary (code|commands)|arbitrary code execution", text)
    if rce_text and family in ("mem", "rce", "web", "other"):
        label, gender, family = "Ejecución remota de código", "f", "rce"
    if family == "auth" and re.search(r"as root|elevated privileges|administrator privileges|system privileges", text):
        family = "priv"
    prod_text = f"{kev.vendor_project} {kev.product}".lower()
    surface = next((s for s, pat in SURFACES if re.search(pat, prod_text)), "general")
    vec = (enr.cvss_vector if enr else None) or ""
    return {"desc": desc, "label": label, "gender": gender, "family": family, "surface": surface, "vector": vec}


def _exposure_sentence(vec):
    if "AV:N" in vec and "PR:N" in vec:
        return "Puede explotarse de forma remota y sin autenticación."
    if "AV:N" in vec:
        return "Puede explotarse de forma remota."
    if "AV:L" in vec:
        return "Requiere acceso local al sistema, por lo que suele usarse junto con otras técnicas de intrusión."
    return ""


def _impact_rows(kev, enr, vec):
    def lvl(metric):
        m = re.search(rf"/{metric}:([HLN])", vec)
        return m.group(1) if m else None

    texts = {
        "C": ("Confidencialidad", "un atacante puede acceder a información sensible o credenciales."),
        "I": ("Integridad", "permite modificar datos, configuraciones o instalar software malicioso."),
        "A": ("Disponibilidad", "puede provocar la interrupción del servicio o del sistema afectado."),
    }
    rows = []
    for key, (area, consequence) in texts.items():
        v = lvl(key)
        if v == "H":
            rows.append({"area": area, "text": f"Alto. {consequence[0].upper()}{consequence[1:]}"})
        elif v == "L":
            rows.append({"area": area, "text": f"Medio. De forma limitada, {consequence}"})
        elif v == "N":
            rows.append({"area": area, "text": "Bajo. Sin impacto directo según la evaluación CVSS."})
    if "AV:N" in vec:
        rows.append({"area": "Exposición", "text": "Alto. Explotable a través de la red" + (" sin autenticación previa." if "PR:N" in vec else " con credenciales de bajo nivel.")})
    elif "AV:L" in vec:
        rows.append({"area": "Exposición", "text": "Medio. Requiere acceso local; suele encadenarse con un acceso inicial previo."})
    if (kev.known_ransomware or "").lower() == "known":
        rows.append({"area": "Ransomware", "text": "Alto. CISA registra su uso en campañas de ransomware conocidas."})
    else:
        rows.append({"area": "Ransomware", "text": "Sin evidencia pública de uso en campañas de ransomware a la fecha."})
    if not vec:
        rows.insert(0, {"area": "Evaluación técnica", "text": "NVD todavía no publicó la evaluación CVSS. Se considera de riesgo alto por estar explotada activamente."})
    return rows


def _affected_products(enr, fallback):
    out = []
    for cpe in (enr.cpes if enr else None) or []:
        parts = cpe.split(":")
        if len(parts) > 5:
            name = f"{parts[3]} {parts[4]}".replace("_", " ").title()
            ver = parts[5] if parts[5] not in ("*", "-") else ""
            item = f"{name} {ver}".strip()
            if item not in out:
                out.append(item)
        if len(out) >= 12:
            break
    return out or [fallback]


SERVER_SURFACES = ("web", "perimetral", "virtualizacion", "general")
CLIENT_SURFACES = ("correo", "navegador")
NETWORK_DEVICE = r"d-link|tp-link|zyxel|mikrotik|router|camera|cámara|nas|qnap|synology|iot|dvr|nvr"


def _names(items, n=2):
    return ", ".join(f"«{x['name']}»" for x in items[:n])


def _apply_fortiguard(cards, fg, cve, short):
    """Reemplaza el texto genérico por la cobertura real que publica FortiGuard para la CVE."""
    by = {x["key"]: x for x in cards}
    if fg.get("ips") and "fortigate" in by and by["fortigate"]["product"].startswith("FortiGate"):
        ids = ", ".join(x["id"] for x in fg["ips"][:2] if x.get("id"))
        by["fortigate"].update(included=True, _s=9, product="FortiGate (IPS FortiGuard)",
                               text=f"FortiGuard IPS ya detecta y bloquea los intentos de explotación de {cve} con la firma {_names(fg['ips'])}"
                                    + (f" (ID {ids})" if ids else "") + f". Verificar que el perfil IPS esté aplicado en las políticas que publican {short}.")
    elif fg.get("ips") and "fortigate" in by:
        by["fortigate"]["text"] += f" FortiGuard IPS cuenta además con la firma {_names(fg['ips'])} para este ataque."
    if fg.get("waf") and "fortiweb" in by:
        by["fortiweb"].update(included=True, _s=8, text=f"FortiWeb tiene firmas específicas para {cve} ({_names(fg['waf'])}) que bloquean las peticiones maliciosas.")
    if "fortiedr" in by:
        parts = []
        if fg.get("endpoint"):
            parts.append(f"FortiClient EMS detecta los equipos vulnerables con la firma de vulnerabilidad {_names(fg['endpoint'], 1)}, para priorizar el parcheo")
        if fg.get("virus"):
            parts.append(f"el antivirus de FortiGuard (FortiEDR, FortiGate y FortiMail) detecta el malware usado en la campaña, como {_names(fg['virus'])}")
        if parts:
            text = "; ".join(parts)
            by["fortiedr"].update(included=True, _s=7, product="FortiClient EMS / FortiEDR", text=text[0].upper() + text[1:] + ".")
    if fg.get("dast"):
        cards.append({"key": "fortidast", "icon": "search", "product": "FortiDAST", "included": True, "_s": 6,
                      "text": f"Detecta {cve} al escanear las aplicaciones web publicadas, para confirmar si el cliente está expuesto."})
    return cards


def fortinet_cards(c, kev=None, cve="", short="", fg=None):
    """Sección "Cómo te protege Fortinet" adaptada a la vulnerabilidad.

    Cada producto de la suite tiene una relevancia según dónde está la falla (perimetral, web, correo,
    endpoint…), el tipo de ataque y el vector CVSS. Los relevantes salen tildados y ordenados; el resto
    queda destildado para que el analista lo sume si quiere.
    """
    s, fam, vec = c["surface"], c["family"], c["vector"]
    vendor = (kev.vendor_project if kev else "") or ""
    prod_text = f"{vendor} {kev.product if kev else ''}".lower()
    own = vendor.lower().startswith("fortinet")
    remote = "AV:N" in vec or not vec
    user_click = "UI:R" in vec or s in CLIENT_SURFACES
    ransomware = bool(kev and (kev.known_ransomware or "").lower() == "known")
    cve = cve or (kev.cve_id if kev else "esta vulnerabilidad")
    short = short or "el sistema afectado"
    cards = []

    def add(key, icon, product, text, score):
        cards.append({"key": key, "icon": icon, "product": product, "text": text, "included": score >= 2, "_s": score})

    # ---------------- FortiGate (NGFW / IPS)
    if own:
        add("fortigate", "shield", "FortiOS / PSIRT Fortinet",
            f"Aplicar la versión corregida indicada en el aviso PSIRT de Fortinet para {cve}. Hasta actualizar, restringir el acceso "
            "a la interfaz de administración y a la VPN SSL solo desde IPs de confianza (local-in policies) y revisar cuentas y configuración.", 5)
    elif s == "perimetral":
        add("fortigate", "shield", "FortiGate (NGFW / IPS)",
            f"Ubicar {short} detrás de políticas que permitan la administración y la VPN solo desde orígenes de confianza, "
            f"con el perfil IPS de FortiGuard activo para bloquear los intentos de explotación de {cve}.", 4)
    elif s in CLIENT_SURFACES and fam == "creds":
        add("fortigate", "shield", "FortiGate (NGFW / IPS)",
            "Bloquear el tráfico SMB/NTLM saliente hacia internet (TCP 445) para impedir que los hashes de credenciales lleguen "
            "al servidor del atacante, y filtrar con FortiGuard Web/DNS los destinos maliciosos.", 5)
    elif s in CLIENT_SURFACES:
        add("fortigate", "shield", "FortiGate (NGFW / IPS)",
            f"Filtrado Web y DNS de FortiGuard e inspección SSL para cortar la descarga del contenido malicioso y la comunicación "
            f"con servidores de comando y control usados al explotar {cve}.", 4)
    elif remote:
        add("fortigate", "shield", "FortiGate (NGFW / IPS)",
            f"Aplicar el perfil IPS con las firmas de FortiGuard para {cve} en las políticas que publican {short}, "
            "para bloquear los intentos de explotación antes de que lleguen al servidor.", 5)
    else:
        add("fortigate", "shield", "FortiGate (segmentación)",
            f"Segmentar la red interna para limitar el movimiento lateral hacia {short}: la falla requiere acceso previo, "
            "por lo que cortar ese camino reduce el riesgo.", 3)

    # ---------------- FortiWeb (WAF)
    if s == "web":
        add("fortiweb", "globe", "FortiWeb (WAF)",
            f"Parcheo virtual: las firmas de FortiWeb bloquean las peticiones HTTP que explotan {cve} en {short} "
            "mientras se aplica la actualización del fabricante.", 5)
    elif re.search(r"exchange|sharepoint|owa|portal|web", prod_text):
        add("fortiweb", "globe", "FortiWeb (WAF)",
            f"Publicar {short} detrás de FortiWeb para filtrar peticiones maliciosas y limitar la exposición de sus servicios web.", 3)
    else:
        add("fortiweb", "globe", "FortiWeb (WAF)",
            "Protección de las aplicaciones web publicadas frente a intentos de explotación.", 0)

    # ---------------- FortiMail
    if s == "correo":
        add("fortimail", "mail", "FortiMail",
            f"Sandboxing de adjuntos y archivos de mensaje (.msg, .eml, documentos de Office) y reescritura de enlaces: "
            f"el correo es el vector de entrada de {cve}.", 5)
    elif s == "navegador" or user_click:
        add("fortimail", "mail", "FortiMail",
            "Reescritura y análisis de enlaces en los correos, que suelen llevar al usuario al sitio que explota la falla.", 3)
    elif ransomware:
        add("fortimail", "mail", "FortiMail",
            "Bloqueo del phishing usado como acceso inicial en las campañas de ransomware que aprovechan esta falla.", 2)
    else:
        add("fortimail", "mail", "FortiMail", "Bloqueo de phishing y sandboxing de adjuntos maliciosos.", 0)

    # ---------------- FortiEDR / FortiClient EMS
    if s in ("perimetral",) or re.search(NETWORK_DEVICE, prod_text):
        add("fortiedr", "monitor", "FortiEDR / FortiClient EMS",
            "Detección de actividad maliciosa en los equipos de la red interna si el atacante logra avanzar desde el perímetro.", 1)
    elif s in CLIENT_SURFACES or s == "so":
        add("fortiedr", "monitor", "FortiEDR / FortiClient EMS",
            f"FortiClient EMS identifica los equipos con versiones vulnerables de {short} para priorizar el parcheo; "
            "FortiEDR bloquea en tiempo real la ejecución de cargas maliciosas tras la explotación.", 5 if fam in ("rce", "mem", "priv") else 4)
    elif fam == "priv":
        add("fortiedr", "monitor", "FortiEDR / FortiClient EMS",
            f"Detección y bloqueo de la elevación de privilegios y de las acciones posteriores en los servidores con {short}.", 4)
    else:
        add("fortiedr", "monitor", "FortiEDR (servidores)",
            f"Protección en el servidor que ejecuta {short}: bloquea procesos y comandos anómalos lanzados después de la explotación, "
            "como shells web o descargas de malware.", 4 if fam in ("rce", "mem", "web") else 2)

    # ---------------- FortiAnalyzer / FortiSIEM
    if fam in ("creds", "auth"):
        add("fortianalyzer", "search", "FortiAnalyzer / FortiSIEM",
            "Correlación de eventos para detectar el uso de credenciales robadas: inicios de sesión desde ubicaciones o equipos "
            "inusuales, y accesos administrativos fuera de horario.", 4)
    elif s == "perimetral" or own:
        add("fortianalyzer", "search", "FortiAnalyzer / FortiSIEM",
            f"Búsqueda en los registros de {short} y del firewall de los indicadores de compromiso publicados para {cve}: "
            "accesos administrativos, cambios de configuración y conexiones a IPs maliciosas.", 4)
    else:
        add("fortianalyzer", "search", "FortiAnalyzer / FortiSIEM",
            f"Búsqueda retrospectiva de intentos de explotación de {cve} y de las alertas IPS asociadas, para saber si el "
            "entorno ya fue atacado antes del parche.", 3)

    # ---------------- FortiNAC
    if re.search(NETWORK_DEVICE, prod_text):
        add("fortinac", "network", "FortiNAC",
            f"Inventario y aislamiento de los dispositivos {vendor} conectados a la red, y bloqueo automático si se detecta un compromiso.", 4)
    elif ransomware or s in ("so", "navegador", "correo"):
        add("fortinac", "network", "FortiNAC",
            "Aislamiento automático de los equipos comprometidos para frenar la propagación dentro de la red.", 2)
    else:
        add("fortinac", "network", "FortiNAC", "Visibilidad de dispositivos y aislamiento automático de equipos comprometidos.", 0)

    if fg:
        cards = _apply_fortiguard(cards, fg, cve, short)
    cards.sort(key=lambda x: -x["_s"])
    for x in cards:
        x.pop("_s")
    return cards


def build_content(kev, enr, alert, fg: dict | None = None) -> dict:
    c = classify(kev, enr)
    prod = product_display(kev.vendor_project, kev.product)
    short = product_short(kev.vendor_project, kev.product)
    explotada = "explotada" if c["gender"] == "f" else "explotado"
    cvss = enr.cvss_score if enr and enr.cvss_score is not None else None
    severity = SEVERITY_ES.get((enr.cvss_severity or "").upper(), "") if enr else ""
    ransomware = (kev.known_ransomware or "").lower() == "known"
    impact = IMPACT_SENTENCE.get(c["family"], IMPACT_SENTENCE["other"])

    subtitle = [kev.cve_id]
    if cvss is not None:
        subtitle.append(f"CVSS {cvss}")
    subtitle.append("Incluida en el catálogo KEV de CISA")

    what = (f"El {fecha_corta(kev.date_added)} CISA incorporó a su catálogo de vulnerabilidades explotadas activamente "
            f"la {kev.cve_id}, una falla de {c['desc']} en {prod}. {impact} {_exposure_sentence(c['vector'])}").strip()
    if ransomware:
        what += " Hay registro de su uso en campañas de ransomware."
    if kev.due_date:
        what += f" CISA fijó el {fecha_corta(kev.due_date)} como plazo de remediación."

    actions = [
        f"Aplicar la actualización o mitigación publicada por {kev.vendor_project} para {short}. Es la única solución completa.",
        SURFACE_ACTION[c["surface"]],
        f"Identificar todos los equipos y servicios con {short}, priorizando los expuestos a internet.",
        FAMILY_ACTION.get(c["family"], DEFAULT_FAMILY_ACTION),
    ]
    if ransomware:
        actions.append("Verificar que las copias de seguridad estén actualizadas y aisladas: esta falla se usa en campañas de ransomware.")

    refs = [{"label": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{kev.cve_id}"},
            {"label": "CISA KEV", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}]
    for u in ((enr.ref_urls if enr else None) or []):
        if "nvd.nist.gov" in u or "cisa.gov" in u:
            continue
        refs.append({"label": "Fabricante" if kev.vendor_project.split()[0].lower() in u.lower() else "Referencia", "url": u})
        if len(refs) >= 5:
            break

    if fg:
        if fg.get("outbreak") and fg["outbreak"].get("url"):
            refs.insert(2, {"label": "FortiGuard Outbreak Alert", "url": fg["outbreak"]["url"]})
        for x in (fg.get("ips") or [])[:1]:
            if x.get("url"):
                refs.insert(2, {"label": f"FortiGuard IPS {x['name']}", "url": x["url"]})

    sev_txt = f" con una puntuación CVSS de {cvss}" + (f" (severidad {severity})" if severity else "") if cvss is not None else ""
    exec_summary = (f"El {fecha_larga(kev.date_added)} CISA confirmó la explotación activa de la {kev.cve_id} en {prod}, "
                    f"una falla de {c['desc']}{sev_txt}. {impact} Vectus recomienda aplicar la actualización del fabricante "
                    f"a la brevedad y, mientras tanto, implementar las medidas compensatorias detalladas en este informe.")

    status = ["Explotación activa confirmada por CISA (catálogo Known Exploited Vulnerabilities)."]
    if kev.due_date:
        status.append(f"Plazo de remediación fijado por CISA: {fecha_larga(kev.due_date)}.")
    if enr and enr.epss is not None:
        status.append(f"Probabilidad de explotación en los próximos 30 días (EPSS): {enr.epss * 100:.2f}%"
                      + (f", por encima del {enr.epss_percentile * 100:.0f}% de las vulnerabilidades conocidas." if enr.epss_percentile else "."))
    status.append("Uso en campañas de ransomware: " + ("confirmado por CISA." if ransomware else "sin evidencia pública a la fecha."))
    status.append("El fabricante publicó actualizaciones o mitigaciones; se deben seguir sus instrucciones para la versión instalada.")

    return {
        # --- Newsletter (cuerpo del mail) ---
        "subject": f"[Alerta Vectus] {c['label']} en {prod} {explotada} activamente ({kev.cve_id})",
        "badge": "ALERTA DE SEGURIDAD · EXPLOTACIÓN ACTIVA",
        "emitted": date.today().isoformat(),
        "title": f"{c['label']} en {prod} {explotada} activamente",
        "subtitle": " · ".join(subtitle),
        "what_happened": what,
        "actions": actions,
        "fortinet_intro": (f"La falla afecta a un producto Fortinet: estos son los pasos y controles para mitigarla"
                           if kev.vendor_project.lower().startswith("fortinet")
                           else f"FortiGuard Labs publicó la alerta «{fg['outbreak']['name']}» y la suite Fortinet ya cuenta con protección para {kev.cve_id}"
                           if fg and fg.get("outbreak")
                           else f"Controles de la suite Fortinet para mitigar {kev.cve_id} mientras se aplica la actualización"),
        "fortinet": fortinet_cards(c, kev, kev.cve_id, short, fg),
        "important": f"Las protecciones de red reducen el riesgo, pero no reemplazan la actualización de {short}.",
        "references": refs,
        # --- Informe (adjunto) ---
        "classification": "Confidencial - Uso Interno del Cliente",
        "executive_summary": exec_summary,
        "technical": {
            "cve": kev.cve_id, "vendor": kev.vendor_project, "product": kev.product,
            "cvss": f"{cvss} ({severity})" if cvss is not None else "Pendiente en NVD",
            "vector": (enr.cvss_vector if enr else None) or "—",
            "epss": f"{enr.epss * 100:.2f}%" if enr and enr.epss is not None else "—",
            "cwe": ", ".join(sorted(set(kev.cwes or []) | set((enr.cwes if enr else None) or []))) or "—",
            "date_added": fecha_corta(kev.date_added), "due_date": fecha_corta(kev.due_date),
            "ransomware": "Sí (conocido)" if ransomware else "Sin evidencia pública",
        },
        "original_description": kev.short_description,
        "status_items": status,
        "impact_intro": "La explotación de esta vulnerabilidad presenta los siguientes riesgos para las organizaciones:",
        "impact_rows": _impact_rows(kev, enr, c["vector"]),
        "affected_products": _affected_products(enr, prod),
        "hardening": HARDENING_BASE + HARDENING_SURFACE.get(c["surface"], []),
        "next_steps": NEXT_STEPS,
        "meta": {"surface": c["surface"], "family": c["family"], "alert_code": alert.code, "score": alert.score,
                 "fortiguard": bool(fg)},
    }
