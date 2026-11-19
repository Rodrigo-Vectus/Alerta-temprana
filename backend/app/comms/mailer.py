"""Envío de comunicados: newsletter HTML como cuerpo (imágenes inline) + informe adjunto.

Dos proveedores, según MAIL_PROVIDER en el .env:
  - smtp  : cualquier servidor SMTP (usuario y contraseña).
  - graph : Microsoft 365 vía Microsoft Graph con OAuth (app registrada con permiso Mail.Send).
            Es la opción recomendada para M365: Microsoft deshabilita por defecto el SMTP AUTH
            con usuario y contraseña a fines de diciembre de 2026.
"""
import base64
import os
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

import httpx

from app.comms.newsletter import inline_images, render_newsletter


def provider():
    return os.getenv("MAIL_PROVIDER", "smtp").strip().lower()


def graph_config():
    return {
        "tenant": os.getenv("GRAPH_TENANT_ID", "").strip(),
        "client_id": os.getenv("GRAPH_CLIENT_ID", "").strip(),
        "client_secret": os.getenv("GRAPH_CLIENT_SECRET", ""),
        "sender": (os.getenv("GRAPH_SENDER", "") or os.getenv("SMTP_FROM", "")).strip(),
    }


def config():
    return {
        "host": os.getenv("SMTP_HOST", "").strip(),
        "port": int(os.getenv("SMTP_PORT", "587") or 587),
        "user": os.getenv("SMTP_USER", "").strip(),
        "password": os.getenv("SMTP_PASSWORD", ""),
        "security": os.getenv("SMTP_SECURITY", "starttls").strip().lower(),   # starttls | ssl | none
        "from_addr": (os.getenv("SMTP_FROM", "") or os.getenv("SMTP_USER", "")).strip(),
        "from_name": os.getenv("SMTP_FROM_NAME", "Vectus · Alertas de Seguridad").strip(),
    }


def is_configured():
    if provider() == "graph":
        g = graph_config()
        return all(g.values())
    c = config()
    return bool(c["host"] and c["from_addr"])


def public_status():
    c = config()
    if provider() == "graph":
        g = graph_config()
        return {"configured": is_configured(), "provider": "graph", "host": "Microsoft Graph (OAuth)", "port": 443,
                "security": "oauth", "from": g["sender"], "from_name": c["from_name"]}
    return {"configured": is_configured(), "provider": "smtp", "host": c["host"], "port": c["port"],
            "security": c["security"], "from": c["from_addr"], "from_name": c["from_name"]}


def plain_text(content: dict) -> str:
    lines = [content["title"], content["subtitle"], "", "¿QUÉ PASÓ?", content["what_happened"], "", "¿QUÉ HACER?"]
    lines += [f"{i:02d}. {a}" for i, a in enumerate(content["actions"], 1)]
    lines += ["", "CÓMO TE PROTEGE FORTINET"]
    lines += [f"- {f['product']}: {f['text']}" for f in content.get("fortinet", []) if f.get("included", True)]
    lines += ["", "EN GRUPO VECTUS TE AYUDAMOS a evaluar tu exposición y activar estas protecciones hoy.",
              "Contactá a tu ejecutivo de cuenta.", "", f"IMPORTANTE: {content['important']}", "", "REFERENCIAS"]
    lines += [f"{r['label']}: {r['url']}" for r in content.get("references", [])]
    lines += ["", "Grupo VECTUS · www.vectus.la"]
    return "\n".join(lines)


def send(content: dict, to: list[str], attachments: list[tuple[str, bytes, str]], subject_prefix: str = "", notice: dict | None = None):
    if not is_configured():
        raise RuntimeError("El correo no está configurado: revisá MAIL_PROVIDER y los datos SMTP_* o GRAPH_* en el .env")
    if provider() == "graph":
        return _send_graph(content, to, attachments, subject_prefix, notice=notice)
    return _send_smtp(content, to, attachments, subject_prefix, notice=notice)


def _graph_payload(content, to, attachments, subject_prefix, notice=None):
    atts = [{"@odata.type": "#microsoft.graph.fileAttachment", "name": name, "contentType": "image/png",
             "contentBytes": base64.b64encode(data).decode(), "contentId": name, "isInline": True}
            for name, data in inline_images()]
    atts += [{"@odata.type": "#microsoft.graph.fileAttachment", "name": fn, "contentType": mime,
              "contentBytes": base64.b64encode(data).decode()} for fn, data, mime in attachments]
    return {"message": {
        "subject": f"{subject_prefix}{content['subject']}",
        "body": {"contentType": "HTML", "content": render_newsletter(content, mode="cid", notice=notice)},
        "toRecipients": [{"emailAddress": {"address": a}} for a in to],
        "attachments": atts,
    }, "saveToSentItems": True}


def _send_graph(content, to, attachments, subject_prefix, client=None, notice=None):
    g = graph_config()
    client = client or httpx.Client(timeout=60)
    tok = client.post(f"https://login.microsoftonline.com/{g['tenant']}/oauth2/v2.0/token", data={
        "client_id": g["client_id"], "client_secret": g["client_secret"],
        "scope": "https://graph.microsoft.com/.default", "grant_type": "client_credentials"})
    if tok.status_code != 200:
        raise RuntimeError(f"Microsoft rechazó las credenciales de la app ({tok.status_code}): {tok.text[:300]}")
    r = client.post(f"https://graph.microsoft.com/v1.0/users/{g['sender']}/sendMail",
                    headers={"Authorization": f"Bearer {tok.json()['access_token']}"},
                    json=_graph_payload(content, to, attachments, subject_prefix, notice))
    if r.status_code != 202:
        raise RuntimeError(f"Microsoft Graph no aceptó el envío ({r.status_code}): {r.text[:300]}")


def _send_smtp(content: dict, to: list[str], attachments: list[tuple[str, bytes, str]], subject_prefix: str = "", notice=None):
    c = config()

    msg = EmailMessage()
    msg["Subject"] = f"{subject_prefix}{content['subject']}"
    msg["From"] = formataddr((c["from_name"], c["from_addr"]))
    msg["To"] = ", ".join(to)
    msg["Message-ID"] = make_msgid(domain=c["from_addr"].split("@")[-1] or "vectus.la")
    text = plain_text(content)
    if notice:
        text = f"AVISO INTERNO PARA EL SOC: {notice['text']}\n{notice['url']}\n\n" + text
    msg.set_content(text)
    msg.add_alternative(render_newsletter(content, mode="cid", notice=notice), subtype="html")
    html_part = msg.get_payload()[1]
    for name, data in inline_images():
        html_part.add_related(data, maintype="image", subtype="png", cid=f"<{name}>", filename=name, disposition="inline")
    for filename, data, mime in attachments:
        maintype, subtype = mime.split("/", 1)
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)

    server = _smtp_connect(c)
    try:
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except Exception:
            pass


# --- Verificación de la configuración (la usa install.sh) -------------------------------------

def _smtp_connect(c):
    ctx = ssl.create_default_context()
    if c["security"] == "ssl":
        server = smtplib.SMTP_SSL(c["host"], c["port"], context=ctx, timeout=30)
    else:
        server = smtplib.SMTP(c["host"], c["port"], timeout=30)
    server.ehlo()
    if c["security"] == "starttls":
        server.starttls(context=ctx)
        server.ehlo()
    if c["user"] and c["password"]:
        server.login(c["user"], c["password"])
    return server


def check(send_to: str | None = None) -> str:
    """Valida las credenciales del proveedor configurado y, opcionalmente, manda un mail simple."""
    if not is_configured():
        raise RuntimeError("El correo no está configurado en el .env")
    if provider() == "graph":
        g = graph_config()
        with httpx.Client(timeout=30) as client:
            tok = client.post(f"https://login.microsoftonline.com/{g['tenant']}/oauth2/v2.0/token", data={
                "client_id": g["client_id"], "client_secret": g["client_secret"],
                "scope": "https://graph.microsoft.com/.default", "grant_type": "client_credentials"})
            if tok.status_code != 200:
                raise RuntimeError(f"Microsoft rechazó las credenciales de la app ({tok.status_code}): {tok.text[:200]}")
            if send_to:
                r = client.post(f"https://graph.microsoft.com/v1.0/users/{g['sender']}/sendMail",
                                headers={"Authorization": f"Bearer {tok.json()['access_token']}"},
                                json={"message": {"subject": "Vectus SAT · prueba de configuración",
                                                  "body": {"contentType": "Text", "content": "El envío de correo de Vectus SAT funciona."},
                                                  "toRecipients": [{"emailAddress": {"address": send_to}}]},
                                      "saveToSentItems": False})
                if r.status_code != 202:
                    raise RuntimeError(f"Microsoft Graph no aceptó el envío ({r.status_code}): {r.text[:200]}")
        return f"Microsoft Graph OK ({g['sender']})" + (f" · prueba enviada a {send_to}" if send_to else "")
    c = config()
    server = _smtp_connect(c)
    try:
        if send_to:
            msg = EmailMessage()
            msg["Subject"] = "Vectus SAT · prueba de configuración"
            msg["From"] = formataddr((c["from_name"], c["from_addr"]))
            msg["To"] = send_to
            msg.set_content("El envío de correo de Vectus SAT funciona.")
            server.send_message(msg)
    finally:
        try:
            server.quit()
        except Exception:
            pass
    return f"SMTP OK ({c['host']}:{c['port']} como {c['user'] or c['from_addr']})" + (f" · prueba enviada a {send_to}" if send_to else "")


if __name__ == "__main__":
    import argparse
    import sys

    p = argparse.ArgumentParser(description="Verificar la configuración de correo")
    p.add_argument("--check", action="store_true", help="Validar credenciales (no envía nada)")
    p.add_argument("--send", metavar="EMAIL", help="Enviar un mail simple de prueba")
    a = p.parse_args()
    try:
        print(check(a.send))
    except Exception as e:  # noqa: BLE001
        print(f"ERROR: {e}")
        sys.exit(1)
