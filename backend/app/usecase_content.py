"""Contenido técnico de los casos de uso: flujo del ataque, playbook genérico y runbook para el SOC.

Todo se arma por plantillas a partir de: superficie afectada (perimetral, web, correo, navegador,
virtualización, sistema operativo), familia de falla (RCE, credenciales, bypass, escalamiento…),
vector CVSS, uso en ransomware y, si existe, la cobertura publicada por FortiGuard.
"""
import re

from app.comms.content import SEVERITY_ES, classify, product_short


def _ctx(kev, enr, fg):
    c = classify(kev, enr)
    vec = c["vector"]
    return {
        **c,
        "cve": kev.cve_id, "vendor": kev.vendor_project, "product": kev.product,
        "short": product_short(kev.vendor_project, kev.product),
        "remote": "AV:N" in vec or not vec, "local": "AV:L" in vec, "noauth": "PR:N" in vec,
        "click": "UI:R" in vec or c["surface"] in ("correo", "navegador"),
        "ransom": (kev.known_ransomware or "").lower() == "known",
        "cvss": enr.cvss_score if enr else None, "sev": SEVERITY_ES.get(((enr.cvss_severity if enr else "") or "").upper(), ""),
        "fg": fg or {},
        "ips": [x["name"] for x in ((fg or {}).get("ips") or [])],
    }


# ============================================================================ FLUJO DEL ATAQUE
def attack_flow(kev, enr, fg=None):
    x = _ctx(kev, enr, fg)
    s, fam, short, cve = x["surface"], x["family"], x["short"], x["cve"]
    st = []

    def add(tactic, mitre, title, desc, cut):
        st.append({"tactic": tactic, "mitre": mitre, "title": title, "desc": desc, "cut": cut})

    # 1. Preparación / reconocimiento
    if x["click"]:
        add("Preparación", "T1566", "El atacante prepara el señuelo",
            "Arma un correo, archivo o sitio web que dispara la falla cuando la víctima lo abre o lo visita." if s != "correo"
            else f"Arma un mensaje o archivo adjunto manipulado dirigido a usuarios de {short}.",
            "Gateway de correo con sandboxing y filtrado web que bloqueen el señuelo antes de llegar al usuario.")
    elif x["local"]:
        add("Acceso previo", "T1078", "El atacante ya tiene un acceso limitado",
            f"Necesita una cuenta o un acceso de bajo privilegio en el equipo con {short} (por ejemplo, tras un phishing o credenciales robadas).",
            "MFA, gestión de cuentas y monitoreo de accesos para impedir ese primer acceso.")
    else:
        add("Reconocimiento", "T1595", f"Búsqueda de {short} expuesto en internet",
            f"Escanea internet de forma masiva (Shodan, escáneres automatizados) para encontrar servicios de {short} accesibles y sus versiones.",
            "No exponer el servicio a internet o limitarlo a IPs de confianza; ocultar banners de versión.")

    # 2. Explotación
    if s == "correo" and fam == "creds":
        add("Acceso a credenciales", "T1187", "La víctima abre el mensaje y se filtra su hash",
            f"Al procesar el contenido manipulado, {short} se conecta al servidor del atacante (SMB/WebDAV) y envía el hash NTLMv2 del usuario, sin la advertencia habitual.",
            "Bloquear SMB (TCP 445) y WebDAV salientes hacia internet en el firewall; aplicar el parche.")
    elif x["click"]:
        add("Ejecución", "T1189" if s == "navegador" else "T1203", f"Se explota {cve} en el equipo de la víctima",
            f"Al abrir el contenido, la falla de {x['desc']} permite ejecutar código con los permisos del usuario.",
            "Parche del software, EDR que bloquee la ejecución y usuarios sin privilegios de administrador.")
    elif x["local"]:
        add("Escalamiento de privilegios", "T1068", f"Explota {cve} para elevar privilegios",
            f"Aprovecha la falla de {x['desc']} para pasar de usuario limitado a root/SYSTEM o administrador del equipo.",
            "Parche, EDR con detección de escalamiento y monitoreo de cuentas privilegiadas.")
    else:
        add("Acceso inicial", "T1190", f"Explotación remota de {cve}",
            f"Envía solicitudes manipuladas a {short} que explotan la falla de {x['desc']}"
            + (" sin necesidad de credenciales." if x["noauth"] else " con credenciales de bajo nivel."),
            "Parche; mientras tanto IPS/WAF con firmas para la CVE" + (f" (p. ej. firma {x['ips'][0]})" if x["ips"] else "") + ".")

    # 3. Ejecución / abuso
    if fam == "creds":
        add("Uso de credenciales", "T1110.002 · T1557", "Crackea o retransmite el hash",
            "Rompe el hash offline para obtener la contraseña, o lo retransmite (relay) para autenticarse como la víctima en otros servicios.",
            "Contraseñas robustas, MFA en todos los accesos, firma SMB/EPA y restricción de NTLM.")
        add("Acceso con cuenta válida", "T1078", "Entra como el usuario legítimo",
            "Usa la cuenta robada en correo, VPN o aplicaciones de la organización, mezclándose con el tráfico normal.",
            "Detección de inicios de sesión anómalos en el SIEM; revocar sesiones y rotar la contraseña.")
    elif fam in ("auth",):
        add("Persistencia", "T1136", "Crea cuentas o cambia la configuración",
            f"Con acceso administrativo a {short}, crea usuarios, reglas o certificados para volver a entrar aunque se aplique el parche.",
            "Revisión de cuentas y configuración tras parchear; alertas de cambios en el SIEM.")
    elif fam != "priv":
        add("Ejecución", "T1059", "Ejecuta comandos en el servidor",
            "Lanza comandos con los permisos del servicio comprometido (shell, PowerShell) y descarga herramientas adicionales.",
            "EDR en el servidor que bloquee procesos hijos anómalos del servicio.")
        add("Persistencia", "T1505.003" if s == "web" else "T1136",
            "Instala una web shell o una puerta trasera" if s == "web" else "Deja una puerta trasera",
            "Deja un archivo o cuenta que le permite volver a entrar aunque luego se aplique el parche.",
            "Búsqueda de archivos y cuentas nuevas; reinstalar si hay compromiso confirmado.")

    # 4. Movimiento lateral
    add("Movimiento lateral", "T1021", "Avanza hacia la red interna",
        f"Usa el equipo comprometido como punto de apoyo para robar más credenciales y llegar a otros servidores." if s != "perimetral"
        else "Desde el equipo perimetral comprometido accede directamente a la red interna, sin pasar por otras barreras.",
        "Segmentación de red, mínimo privilegio y monitoreo de conexiones internas inusuales.")

    # 5. Impacto
    if x["ransom"]:
        add("Impacto", "T1486", "Despliega ransomware",
            "CISA registra el uso de esta falla en campañas de ransomware: cifrado de servidores y extorsión con datos robados.",
            "Copias de seguridad aisladas e inmutables, EDR con protección anti-ransomware y plan de respuesta probado.")
    else:
        add("Impacto", "T1041 · T1486", "Robo de información o interrupción del servicio",
            "Según el objetivo: exfiltración de datos, fraude con cuentas robadas, cifrado de equipos o uso del servidor para otros ataques.",
            "DLP y monitoreo de tráfico saliente, copias de seguridad y respuesta a incidentes.")

    facts = [
        ("Vector", "Red / internet" if x["remote"] and not x["local"] else "Local (requiere acceso previo)" if x["local"] else "—"),
        ("Autenticación previa", "No requiere" if x["noauth"] else "Requiere" if x["vector"] else "—"),
        ("Interacción del usuario", "Sí (abrir/visitar)" if x["click"] else "No"),
        ("Uso en ransomware", "Sí (CISA)" if x["ransom"] else "Sin evidencia pública"),
    ]
    return {"stages": st, "facts": [{"k": k, "v": v} for k, v in facts]}


# ============================================================================ PLAYBOOK (genérico)
HUNT = {
    "web": ["Revisar los logs de acceso del servidor web y del WAF en busca de peticiones anómalas dirigidas a {short} (parámetros extraños, codificaciones inusuales, rutas administrativas).",
            "Buscar archivos creados o modificados recientemente en los directorios publicados (posibles web shells)."],
    "perimetral": ["Revisar en los logs de {short} los accesos administrativos, inicios de sesión VPN y cambios de configuración de los últimos 30 días.",
                   "Verificar que no existan cuentas locales, reglas o certificados nuevos no creados por el equipo."],
    "correo": ["Buscar en el gateway de correo los mensajes con adjuntos o archivos de mensaje (.msg, .eml) recibidos desde la publicación.",
               "Revisar en los logs del firewall conexiones salientes SMB/WebDAV desde estaciones hacia internet."],
    "navegador": ["Revisar en el EDR procesos hijos inusuales lanzados por el navegador (PowerShell, cmd, scripts).",
                  "Buscar en el proxy o filtrado web accesos a dominios recién registrados o clasificados como maliciosos."],
    "virtualizacion": ["Revisar los logs de la plataforma (vCenter/ESXi o backup): inicios de sesión, usuarios creados y comandos ejecutados.",
                       "Verificar la integridad de las copias de seguridad y que no haya trabajos borrados o modificados."],
    "so": ["Revisar en los equipos afectados la creación de servicios, tareas programadas y cuentas nuevas.",
           "Buscar ejecución de binarios desde rutas temporales o de usuario."],
    "general": ["Revisar los registros de {short} en busca de errores, accesos o comandos inusuales desde la fecha de publicación."],
}
CONTAIN = {
    "web": "Si no se puede parchear de inmediato, publicar {short} detrás de un WAF con reglas de parcheo virtual o restringir el acceso desde internet en el firewall.",
    "perimetral": "Restringir en el firewall la administración y la VPN de {short} a IPs de confianza y deshabilitar los servicios expuestos que no se usen.",
    "correo": "Bloquear en el gateway de correo los adjuntos de riesgo y, en el firewall, el tráfico SMB/WebDAV saliente (TCP 445) hacia internet.",
    "navegador": "Forzar la actualización de los navegadores y bloquear sitios maliciosos con el proxy o filtrado web.",
    "virtualizacion": "Aislar las interfaces de administración en una red de gestión y limitar el acceso a los administradores autorizados.",
    "so": "Aislar de la red los equipos con indicios de compromiso hasta completar la revisión.",
    "general": "Aplicar las mitigaciones indicadas por el fabricante o aislar el sistema afectado hasta parchear.",
}


def _step(sid, text, hint=None):
    return {"id": sid, "text": text, "hint": hint, "done": False, "done_by": None, "done_at": None}


def playbook(kev, enr, fg=None):
    x = _ctx(kev, enr, fg)
    s, fam, short, cve = x["surface"], x["family"], x["short"], x["cve"]
    fmt = lambda t: t.format(short=short, cve=cve)
    fgd = x["fg"]
    secs = [{"id": "alcance", "title": "1. Alcance y exposición", "steps": [
        _step("alcance-1", f"Identificar en cada cliente los activos con {short} y su versión (CMDB, escáner de vulnerabilidades o inventario del EDR)."),
        _step("alcance-2", f"Comparar las versiones instaladas con las afectadas según el aviso del fabricante para {cve}."),
        _step("alcance-3", "Determinar cuáles están expuestos a internet y priorizarlos."),
    ]}]

    det = [_step("det-ips", f"Confirmar que el IPS del firewall perimetral tenga firmas actualizadas para {cve} y que estén en modo bloqueo en las políticas que protegen {short}.",
                 f"Ej. Fortinet: firma FortiGuard IPS «{x['ips'][0]}»." if x["ips"] else None),
           _step("det-siem", f"Buscar en el SIEM, en los últimos 30 días, eventos del IPS/WAF asociados a {cve} para detectar intentos previos.")]
    if fgd.get("endpoint"):
        det.append(_step("det-vuln", "Listar en la consola del EDR o del escáner de vulnerabilidades los equipos detectados como vulnerables.",
                         f"Ej. Fortinet: FortiClient EMS, firma «{fgd['endpoint'][0]['name']}»."))
    if s == "web":
        det.append(_step("det-dast", "Escanear las aplicaciones web publicadas con un escáner de vulnerabilidades web (DAST) para confirmar la exposición.",
                         "Ej. Fortinet: FortiDAST." if fgd.get("dast") else None))
    det += [_step(f"det-hunt-{i}", fmt(t)) for i, t in enumerate(HUNT.get(s, HUNT["general"]), 1)]
    secs.append({"id": "deteccion", "title": "2. Detección y búsqueda de amenazas", "steps": det})

    cont = [_step("cont-1", fmt(CONTAIN.get(s, CONTAIN["general"])))]
    if fgd.get("virus"):
        names = ", ".join(v["name"] for v in sorted(fgd["virus"], key=lambda v: 0 if "ransom" in v["name"].lower() else 1)[:2])
        cont.append(_step("cont-av", "Verificar que el antivirus/EDR de servidores, correo y perímetro esté actualizado para detectar el malware usado en la campaña.",
                          f"Ej. Fortinet: firmas {names}."))
    cont.append(_step("cont-iso", "Si se detecta compromiso, aislar el equipo desde el EDR o el control de acceso a red (NAC) y preservar evidencia antes de remediar."))
    secs.append({"id": "contencion", "title": "3. Contención", "steps": cont})

    rem = [_step("rem-1", f"Aplicar la actualización o mitigación de {x['vendor']} en todos los activos identificados."),
           _step("rem-2", "Documentar por cliente la fecha de aplicación y la versión final.")]
    if fam in ("creds", "auth"):
        rem.append(_step("rem-cred", "Rotar las credenciales y revocar sesiones/tokens que pudieron exponerse, empezando por cuentas privilegiadas."))
    if x["ransom"]:
        rem.append(_step("rem-bkp", "Verificar copias de seguridad recientes, aisladas y restaurables (uso conocido en ransomware)."))
    secs.append({"id": "remediacion", "title": "4. Erradicación y remediación", "steps": rem})

    secs.append({"id": "verificacion", "title": "5. Verificación y cierre", "steps": [
        _step("ver-1", "Confirmar que la versión instalada ya no es vulnerable (reescaneo o verificación manual)."),
        _step("ver-2", "Mantener monitoreo reforzado de los activos durante 30 días."),
        _step("ver-3", "Registrar lecciones aprendidas y cerrar el caso."),
    ]})
    return secs


# ============================================================================ RUNBOOK (técnico)
def _sla(x, score):
    critical = (x["cvss"] or 0) >= 9 or score >= 80 or x["ransom"]
    if critical:
        return "Crítica", [("Triage y confirmación de exposición", "1 hora"), ("Contención en activos expuestos", "4 horas"),
                           ("Parche en activos expuestos", "72 horas"), ("Parche en el resto", "7 días")]
    return "Alta", [("Triage y confirmación de exposición", "4 horas"), ("Contención en activos expuestos", "24 horas"),
                    ("Parche en activos expuestos", "7 días"), ("Parche en el resto", "30 días")]


VERSION_CMDS = {
    "web": ("bash", "# Identificar servicios web y versión expuesta\nnmap -sV -p 80,443,8080,8443 <rango_o_host>\ncurl -sI https://<host> | grep -iE 'server|x-powered-by'"),
    "perimetral": ("text", "FortiGate (FortiOS):   get system status\nCisco ASA / IOS:       show version\nPalo Alto (PAN-OS):    show system info\nCheck Point (Gaia):    show version all   |   fw ver\nOtros: consultar la versión desde la consola de administración del equipo."),
    "correo": ("powershell", "# Versión de Microsoft 365 Apps / Office (Click-to-Run) en cada equipo\nGet-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Office\\ClickToRun\\Configuration' |\n  Select-Object VersionToReport, CDNBaseUrl"),
    "navegador": ("powershell", "# Versión de Chrome y Edge instalada\n(Get-Item 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe').VersionInfo.ProductVersion\n(Get-Item 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe').VersionInfo.ProductVersion"),
    "virtualizacion": ("bash", "# En cada host ESXi (SSH)\nvmware -vl\nesxcli system version get"),
    "so": ("powershell", "# Windows: últimos parches instalados\nGet-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10\n# Linux (bash):  uname -r ; dpkg -l | grep <paquete>   o   rpm -q <paquete>"),
    "general": ("text", "Consultar la versión instalada desde la consola del producto o el inventario del escáner de vulnerabilidades,\ny compararla con la tabla de versiones afectadas del aviso del fabricante."),
}


def _hunting(x):
    cve, sig = x["cve"], (x["ips"][0] if x["ips"] else None)
    q = []
    ips_filter_spl = f'(cve="{cve}"' + (f' OR attack="{sig}"' if sig else "") + ")"
    ips_filter_kql = f'Message has "{cve}"' + (f' or Activity has "{sig}"' if sig else "")
    q.append({"title": "Intentos de explotación registrados por IPS / WAF (30 días)", "items": [
        ("Splunk (SPL)", "spl", f'index=* sourcetype IN ("fortigate*","pan*","cisco*","*waf*") {ips_filter_spl} earliest=-30d\n| stats count min(_time) as primero max(_time) as ultimo by src_ip, dest_ip, action\n| sort - count'),
        ("Microsoft Sentinel (KQL)", "kql", f'CommonSecurityLog\n| where TimeGenerated > ago(30d)\n| where {ips_filter_kql}\n| summarize intentos=count(), primero=min(TimeGenerated), ultimo=max(TimeGenerated)\n    by SourceIP, DestinationIP, DeviceAction\n| order by intentos desc'),
    ] + ([("FortiAnalyzer (filtro de Log View → IPS)", "text", f"attack={sig}")] if sig else [])})

    s, fam = x["surface"], x["family"]
    if fam in ("rce", "mem", "web") and s in ("web", "general", "virtualizacion", "perimetral"):
        q.append({"title": "Procesos sospechosos lanzados por el servicio (post-explotación)", "items": [
            ("Microsoft Defender / Sentinel (KQL)", "kql", 'DeviceProcessEvents\n| where Timestamp > ago(30d)\n| where InitiatingProcessFileName in~ ("w3wp.exe","php-cgi.exe","php.exe","httpd.exe","java.exe","tomcat9.exe","node.exe")\n| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","certutil.exe","bitsadmin.exe","whoami.exe","net.exe")\n| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine'),
            ("Sysmon / Windows (Splunk)", "spl", 'index=* (EventCode=1 OR EventCode=4688) (ParentImage="*\\\\w3wp.exe" OR ParentImage="*\\\\php-cgi.exe" OR ParentImage="*\\\\httpd.exe" OR ParentImage="*\\\\java.exe")\n  (Image="*\\\\cmd.exe" OR Image="*\\\\powershell.exe" OR Image="*\\\\certutil.exe")\n| table _time host ParentImage Image CommandLine'),
        ]})
    if s == "web":
        q.append({"title": "Web shells y archivos modificados", "items": [
            ("Linux", "bash", "find /var/www /usr/share/nginx /srv -type f \\( -name '*.php' -o -name '*.jsp' -o -name '*.aspx' \\) -mtime -30 -ls\ngrep -rlE 'eval\\(|base64_decode\\(|system\\(|shell_exec\\(|passthru\\(' /var/www 2>/dev/null"),
            ("Windows (IIS/Apache)", "powershell", "Get-ChildItem C:\\inetpub, C:\\xampp\\htdocs -Recurse -Include *.php,*.aspx,*.jsp -ErrorAction SilentlyContinue |\n  Where-Object LastWriteTime -gt (Get-Date).AddDays(-30) |\n  Select-Object FullName, LastWriteTime"),
            ("Logs de acceso (Linux)", "bash", "grep -iE '(%[0-9a-f]{2}){4,}|cmd=|/bin/(ba)?sh|powershell|allow_url_include|auto_prepend_file' /var/log/{nginx,apache2,httpd}/access*.log"),
        ]})
    if fam == "creds" or s == "correo":
        q.append({"title": "Filtración de hashes NTLM y uso de credenciales", "items": [
            ("Conexiones SMB salientes a internet (KQL)", "kql", 'DeviceNetworkEvents\n| where Timestamp > ago(30d)\n| where RemotePort in (445, 139) and RemoteIPType == "Public"\n| summarize conexiones=count() by DeviceName, InitiatingProcessFileName, RemoteIP\n| order by conexiones desc'),
            ("Firewall (Splunk)", "spl", 'index=* dest_port IN (445,139) NOT (dest_ip="10.0.0.0/8" OR dest_ip="172.16.0.0/12" OR dest_ip="192.168.0.0/16") earliest=-30d\n| stats count by src_ip, dest_ip, action'),
            ("Inicios de sesión NTLM inusuales (Windows 4624)", "kql", 'SecurityEvent\n| where TimeGenerated > ago(30d) and EventID == 4624\n| where AuthenticationPackageName == "NTLM" and LogonType in (3, 10)\n| summarize logins=count(), origenes=make_set(IpAddress, 20) by TargetUserName\n| where array_length(origenes) > 3'),
        ]})
    if fam in ("auth", "priv") or s == "perimetral":
        q.append({"title": "Cuentas y privilegios", "items": [
            ("Windows: cuentas creadas y agregadas a grupos privilegiados", "kql", 'SecurityEvent\n| where TimeGenerated > ago(30d)\n| where EventID in (4720, 4728, 4732, 4756, 4672)\n| project TimeGenerated, Computer, EventID, Account, TargetUserName, SubjectUserName'),
            ("Linux: escalamiento y accesos", "bash", "last -a | head -50\ngrep -E 'sudo|su\\[|useradd|usermod' /var/log/auth.log* /var/log/secure* 2>/dev/null | tail -100\nfind / -xdev -perm -4000 -newermt \"$(date -d '-30 days' +%F)\" 2>/dev/null"),
        ]})
    if s == "navegador":
        q.append({"title": "Procesos lanzados por el navegador", "items": [
            ("Microsoft Defender / Sentinel (KQL)", "kql", 'DeviceProcessEvents\n| where Timestamp > ago(30d)\n| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe")\n| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","mshta.exe","rundll32.exe")\n| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine'),
        ]})
    if s == "virtualizacion":
        q.append({"title": "Actividad en la plataforma de virtualización", "items": [
            ("ESXi (SSH)", "bash", "esxcli system account list\ngrep -iE 'login|password|account' /var/log/hostd.log /var/log/auth.log | tail -100\ntail -200 /var/log/shell.log"),
        ]})
    if s == "so":
        q.append({"title": "Persistencia en Windows", "items": [
            ("Servicios y tareas programadas nuevas (KQL)", "kql", 'SecurityEvent\n| where TimeGenerated > ago(30d)\n| where EventID in (4697, 4698)\n| project TimeGenerated, Computer, EventID, Account, EventData'),
            ("En el equipo (PowerShell)", "powershell", "Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=(Get-Date).AddDays(-30)} |\n  Select-Object TimeCreated, Message\nGet-ScheduledTask | Where-Object Date -gt (Get-Date).AddDays(-30)"),
        ]})
    return q


def _containment(x):
    s, fam, short = x["surface"], x["family"], x["short"]
    out = [{"title": "Bloquear IPs atacantes identificadas en el hunting", "items": [
        ("FortiGate (FortiOS CLI)", "text", 'config firewall address\n    edit "IOC-' + x["cve"] + '-01"\n        set subnet <IP_ATACANTE> 255.255.255.255\n    next\nend\n# Agregar el objeto a un grupo usado en una política de bloqueo (deny) de entrada y salida'),
        ("Linux (iptables)", "bash", "iptables -I INPUT -s <IP_ATACANTE> -j DROP\niptables -I OUTPUT -d <IP_ATACANTE> -j DROP"),
        ("Windows Firewall", "powershell", 'New-NetFirewallRule -DisplayName "IOC ' + x["cve"] + '" -Direction Inbound -RemoteAddress <IP_ATACANTE> -Action Block\nNew-NetFirewallRule -DisplayName "IOC ' + x["cve"] + ' (salida)" -Direction Outbound -RemoteAddress <IP_ATACANTE> -Action Block'),
    ]}]
    if s == "correo" or fam == "creds":
        out.append({"title": "Bloquear la filtración de hashes NTLM", "items": [
            ("Windows Firewall (por GPO o en cada equipo)", "powershell", 'New-NetFirewallRule -DisplayName "Bloquear SMB saliente a internet" -Direction Outbound `\n  -Protocol TCP -RemotePort 445 -RemoteAddress Internet -Action Block'),
            ("GPO", "text", "Configuración del equipo > Directivas > Configuración de Windows > Configuración de seguridad > Directivas locales >\nOpciones de seguridad > Seguridad de red: restringir NTLM: tráfico NTLM saliente hacia servidores remotos = Auditar (luego Denegar)"),
            ("Firewall perimetral", "text", "Política de salida que deniegue TCP 445/139 y WebDAV (80/443 hacia destinos no categorizados) desde las redes de usuarios hacia internet."),
        ]})
    if s in ("web", "perimetral"):
        out.append({"title": f"Reducir la exposición de {short}", "items": [
            ("Firewall / WAF", "text", f"1. Restringir el acceso a {short} desde internet solo a los orígenes necesarios.\n2. Publicarlo detrás de un WAF con reglas de parcheo virtual para {x['cve']}.\n3. Deshabilitar la interfaz de administración desde internet."),
        ]})
    out.append({"title": "Aislamiento de equipos comprometidos", "items": [
        ("Procedimiento", "text", "1. Aislar el equipo desde el EDR (o mover a VLAN de cuarentena desde el NAC/switch).\n2. NO apagarlo: preservar memoria y conexiones activas.\n3. Registrar hora, responsable y motivo del aislamiento en el caso."),
    ]})
    return out


def runbook(kev, enr, fg, alert, refs=None):
    x = _ctx(kev, enr, fg)
    sev, sla = _sla(x, alert.score)
    cpes = []
    for cpe in ((enr.cpes if enr else None) or [])[:12]:
        p = cpe.split(":")
        if len(p) > 5:
            item = f"{p[3]} {p[4]} {p[5] if p[5] not in ('*', '-') else ''}".replace("_", " ").strip()
            if item not in cpes:
                cpes.append(item)

    secs = []
    secs.append({"id": "datos", "title": "0. Datos del caso", "blocks": [
        {"type": "table", "rows": [
            ["CVE", x["cve"]], ["Producto", f"{x['vendor']} {x['product']}"],
            ["Tipo de falla", x["desc"]], ["CVSS", f"{x['cvss']} ({x['sev']})" if x["cvss"] is not None else "Pendiente en NVD"],
            ["Vector CVSS", x["vector"] or "—"], ["CWE", ", ".join(sorted(set(kev.cwes or []) | set((enr.cwes if enr else None) or []))) or "—"],
            ["Agregada a CISA KEV", f"{kev.date_added:%d/%m/%Y}" if kev.date_added else "—"],
            ["Plazo CISA", f"{kev.due_date:%d/%m/%Y}" if kev.due_date else "—"],
            ["Ransomware", "Uso conocido" if x["ransom"] else "Sin evidencia pública"],
            ["Puntaje Vectus", f"{alert.score}/100"],
        ]},
        {"type": "text", "text": f"Severidad operativa: {sev}. Tiempos objetivo sugeridos (ajustables por contrato):"},
        {"type": "table", "head": ["Actividad", "Plazo"], "rows": [list(r) for r in sla]},
    ] + ([{"type": "list", "title": "Productos/versiones según NVD", "items": cpes}] if cpes else [])})

    secs.append({"id": "triage", "title": "1. Triage (primera hora)", "blocks": [
        {"type": "check", "items": [
            "Confirmar que el cliente usa el producto afectado y en qué versión.",
            "Identificar activos expuestos a internet (escaneo externo, inventario, firewall).",
            "Revisar si el IPS/WAF ya registró intentos contra esos activos (sección 2).",
            "Clasificar: (a) no afectado, (b) afectado sin indicios, (c) afectado con indicios de explotación → incidente.",
            "Registrar la clasificación en «Seguimiento por cliente».",
        ]},
        {"type": "code", "title": "Verificar versión instalada", "lang": VERSION_CMDS.get(x["surface"], VERSION_CMDS["general"])[0],
         "code": VERSION_CMDS.get(x["surface"], VERSION_CMDS["general"])[1]},
    ]})

    hunt = _hunting(x)
    secs.append({"id": "hunting", "title": "2. Detección y hunting", "blocks":
                 [{"type": "text", "text": "Ajustar índices, nombres de tablas y rangos de IP al SIEM y la red de cada cliente. Buscar al menos 30 días hacia atrás."}]
                 + [{"type": "code", "title": f"{g['title']} · {t}", "lang": lang, "code": code} for g in hunt for t, lang, code in g["items"]]})

    cont = _containment(x)
    secs.append({"id": "contencion", "title": "3. Contención", "blocks":
                 [{"type": "code", "title": f"{g['title']} · {t}", "lang": lang, "code": code} for g in cont for t, lang, code in g["items"]]})

    erad = [f"Aplicar la versión corregida publicada por {x['vendor']} (ver referencias) en todos los activos afectados.",
            "Si había indicios de compromiso: reinstalar desde una imagen limpia en lugar de solo parchear.",
            "Eliminar web shells, cuentas, tareas y servicios identificados en el hunting."]
    if x["family"] in ("creds", "auth"):
        erad += ["Resetear contraseñas de las cuentas expuestas y revocar sesiones activas.",
                 "Microsoft Entra ID: Revoke-MgUserSignInSession -UserId <usuario@dominio> (módulo Microsoft.Graph)."]
    if x["ransom"]:
        erad.append("Validar copias de seguridad fuera de línea antes de restaurar cualquier sistema.")
    secs.append({"id": "erradicacion", "title": "4. Erradicación", "blocks": [{"type": "check", "items": erad}]})

    secs.append({"id": "verificacion", "title": "5. Recuperación y verificación", "blocks": [{"type": "check", "items": [
        "Repetir la verificación de versión (sección 1) y confirmar que ya no es vulnerable.",
        "Reescanear con el escáner de vulnerabilidades / DAST.",
        "Repetir las búsquedas de la sección 2 a los 7 y 30 días.",
        "Quitar reglas temporales de contención que ya no sean necesarias (documentarlo).",
    ]}]})

    secs.append({"id": "evidencias", "title": "6. Evidencias a preservar (si hay indicios de compromiso)", "blocks": [{"type": "check", "items": [
        "Logs del servicio afectado, del firewall/IPS/WAF y del SIEM del período (exportar y calcular hash SHA-256).",
        "Volcado de memoria del equipo antes de apagarlo o reiniciarlo.",
        "Imagen de disco o snapshot de la VM.",
        "Lista de procesos, conexiones de red y tareas programadas al momento de la detección.",
        "Cadena de custodia: quién, cuándo y dónde se guardó cada evidencia.",
    ]}]})

    secs.append({"id": "escalamiento", "title": "7. Escalamiento y comunicación", "blocks": [
        {"type": "table", "head": ["Situación", "Acción"], "rows": [
            ["Cliente no afectado", "Registrar en el seguimiento y cerrar para ese cliente."],
            ["Afectado sin indicios", "Coordinar parche dentro del plazo; contención temporal si está expuesto."],
            ["Indicios de explotación", "Declarar incidente, notificar al contacto del cliente y al responsable del SOC de inmediato; iniciar respuesta a incidentes."],
            ["Ransomware / exfiltración", "Escalar a gerencia de Vectus y del cliente; evaluar obligaciones legales de notificación."],
        ]},
    ]})

    secs.append({"id": "cierre", "title": "8. Criterios de cierre", "blocks": [{"type": "check", "items": [
        "Todos los clientes clasificados en «Seguimiento por cliente».",
        "Activos afectados parcheados o con excepción documentada.",
        "Sin indicios de compromiso, o incidente derivado abierto y documentado.",
        "Playbook completo y notas de cierre cargadas.",
    ]}]})

    if refs:
        secs.append({"id": "refs", "title": "9. Referencias", "blocks": [{"type": "links", "items": refs}]})
    return secs


def runbook_markdown(code, title, sections):
    out = [f"# Runbook {code}", f"**{title}**", ""]
    for s in sections:
        out.append(f"## {s['title']}")
        for b in s["blocks"]:
            if b["type"] == "text":
                out += [b["text"], ""]
            elif b["type"] in ("check", "list"):
                if b.get("title"):
                    out.append(f"**{b['title']}**")
                out += [f"- [ ] {i}" if b["type"] == "check" else f"- {i}" for i in b["items"]] + [""]
            elif b["type"] == "table":
                head = b.get("head") or ["", ""]
                out += ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
                out += ["| " + " | ".join(str(c) for c in r) + " |" for r in b["rows"]] + [""]
            elif b["type"] == "code":
                out += [f"**{b['title']}**", f"```{b['lang']}", b["code"], "```", ""]
            elif b["type"] == "links":
                out += [f"- [{r['label']}]({r['url']})" for r in b["items"]] + [""]
    return "\n".join(out)
