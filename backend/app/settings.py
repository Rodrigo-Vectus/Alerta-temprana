"""Configuración del envío automático, editable desde la consola (tabla settings)."""
import os

from app.models import Setting

KEY = "notifications"
DEFAULTS = {
    "auto_send": True,                       # enviar automáticamente a todos los contactos
    "delay_minutes": 30,                     # ventana para que el SOC revise o cancele
    "min_score": int(os.getenv("ALERT_THRESHOLD", "60")),
    "soc_emails": [e.strip() for e in os.getenv("SOC_EMAILS", os.getenv("ADMIN_EMAIL", "")).split(",") if e.strip()],
    "attach_docx": False,                    # además del PDF, adjuntar el DOCX
    "public_url": os.getenv("PUBLIC_URL", "http://192.168.44.129").rstrip("/"),
}


def get_settings(db) -> dict:
    row = db.get(Setting, KEY)
    return {**DEFAULTS, **(row.value if row else {})}


def save_settings(db, values: dict, user_email: str) -> dict:
    current = get_settings(db)
    merged = {**current, **{k: v for k, v in values.items() if k in DEFAULTS}}
    row = db.get(Setting, KEY)
    if row is None:
        db.add(Setting(key=KEY, value=merged, updated_by=user_email))
    else:
        row.value, row.updated_by = merged, user_email
    db.commit()
    return merged
