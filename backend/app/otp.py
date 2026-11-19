"""Ingreso sin contraseña: código de un solo uso (OTP) enviado por mail.

- Solo se genera y envía para usuarios existentes y activos. La API responde lo mismo
  exista o no el correo, para que no se pueda averiguar quién tiene acceso.
- Se guarda únicamente el HMAC del código. Vence a los 10 minutos, admite 5 intentos
  y se invalida al usarse o al pedir uno nuevo.
- Límites: un código por minuto y 6 por hora por usuario (más el límite por IP de nginx).

Emergencia (sin correo): docker compose exec backend python -m app.otp usuario@empresa.com
"""
import hashlib
import hmac
import logging
import os
import secrets
from datetime import timedelta
from html import escape

from sqlalchemy import func, select, update

from app.auth import now_utc
from app.db import SessionLocal
from app.models import LoginCode, User

log = logging.getLogger("otp")

CODE_TTL_MIN = int(os.getenv("OTP_TTL_MINUTES", "10"))
MAX_ATTEMPTS = 5
RESEND_SECONDS = 60
MAX_PER_HOUR = 6
_KEY = os.environ["JWT_SECRET"].encode()


def _hash(user_id: int, code: str) -> str:
    return hmac.new(_KEY, f"{user_id}:{code}".encode(), hashlib.sha256).hexdigest()


def _new_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def issue(db, user: User, ip: str | None) -> str | None:
    """Genera un código nuevo para el usuario (invalida los anteriores). None si superó el límite."""
    now = now_utc()
    last = db.scalar(select(func.max(LoginCode.created_at)).where(LoginCode.user_id == user.id))
    if last and (now - last).total_seconds() < RESEND_SECONDS:
        return None
    recent = db.scalar(select(func.count()).select_from(LoginCode)
                       .where(LoginCode.user_id == user.id, LoginCode.created_at > now - timedelta(hours=1)))
    if recent >= MAX_PER_HOUR:
        return None
    db.execute(update(LoginCode).where(LoginCode.user_id == user.id, LoginCode.used_at.is_(None))
               .values(used_at=now))
    code = _new_code()
    db.add(LoginCode(user_id=user.id, code_hash=_hash(user.id, code), ip=ip,
                     expires_at=now + timedelta(minutes=CODE_TTL_MIN), created_at=now))
    db.commit()
    return code


def verify(db, user: User, code: str) -> str:
    """Devuelve 'ok', 'invalid' o 'too_many'. Consume el código si es correcto."""
    now = now_utc()
    lc = db.scalar(select(LoginCode).where(LoginCode.user_id == user.id, LoginCode.used_at.is_(None),
                                           LoginCode.expires_at > now)
                   .order_by(LoginCode.created_at.desc()).limit(1))
    if not lc:
        return "invalid"
    if lc.attempts >= MAX_ATTEMPTS:
        lc.used_at = now
        db.commit()
        return "too_many"
    if hmac.compare_digest(lc.code_hash, _hash(user.id, code)):
        lc.used_at = now
        db.commit()
        return "ok"
    lc.attempts += 1
    if lc.attempts >= MAX_ATTEMPTS:
        lc.used_at = now
        db.commit()
        return "too_many"
    db.commit()
    return "invalid"


def email_body(user: User, code: str, ip: str | None, public_url: str) -> tuple[str, str, str]:
    """Asunto, texto plano y HTML del mail con el código."""
    subject = f"{code} es tu código de ingreso a Vectus SAT"
    name = user.full_name.split(" ")[0] if user.full_name and user.full_name != "Administrador" else ""
    hello = f"Hola {name}," if name else "Hola,"
    where = f" desde la IP {ip}" if ip else ""
    text = (f"{hello}\n\nTu código para ingresar a Vectus SAT es: {code}\n\n"
            f"Vence en {CODE_TTL_MIN} minutos y sirve una sola vez.\n"
            f"Se pidió{where}. Si no fuiste vos, ignorá este mail: nadie puede entrar sin el código.\n\n"
            f"{public_url}\n\nVectus SOC · Sistema de Alerta Temprana")
    digits = "".join(
        f'<td style="width:44px;height:54px;background:#0f1d33;border:1px solid #1f3a63;border-radius:10px;'
        f'font:700 28px \'Courier New\',monospace;color:#ffffff;text-align:center;">{d}</td>'
        f'<td style="width:8px;"></td>' for d in code)
    html = f"""<!DOCTYPE html><html lang="es"><body style="margin:0;padding:0;background:#eef2f8;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#eef2f8;padding:32px 12px;">
<tr><td align="center">
<table role="presentation" width="480" cellpadding="0" cellspacing="0" style="max-width:480px;width:100%;background:#ffffff;border-radius:14px;overflow:hidden;font-family:Arial,Helvetica,sans-serif;">
<tr><td style="height:4px;background:linear-gradient(90deg,#1d4ed8,#06b6d4);background-color:#1d4ed8;"></td></tr>
<tr><td style="padding:28px 32px 8px;">
  <div style="font:800 17px Arial,sans-serif;color:#0b1b33;letter-spacing:.04em;">VECTUS SAT</div>
  <div style="font:11px 'Courier New',monospace;color:#64748b;letter-spacing:.12em;text-transform:uppercase;">Sistema de Alerta Temprana</div>
</td></tr>
<tr><td style="padding:18px 32px 4px;font-size:15px;color:#1e293b;line-height:1.6;">
  {escape(hello)}<br>usá este código para ingresar a la consola:
</td></tr>
<tr><td align="center" style="padding:18px 32px;">
  <table role="presentation" cellpadding="0" cellspacing="0"><tr>{digits}</tr></table>
</td></tr>
<tr><td style="padding:4px 32px 22px;font-size:13px;color:#475569;line-height:1.6;">
  Vence en <b>{CODE_TTL_MIN} minutos</b> y sirve una sola vez.<br>
  Se pidió{escape(where)}. Si no fuiste vos, ignorá este mail: nadie puede entrar sin el código.
</td></tr>
<tr><td style="padding:14px 32px;background:#f8fafc;border-top:1px solid #e2e8f0;font:11px 'Courier New',monospace;color:#94a3b8;">
  <a href="{escape(public_url)}" style="color:#1d4ed8;text-decoration:none;">{escape(public_url)}</a> · Vectus SOC
</td></tr>
</table></td></tr></table></body></html>"""
    return subject, text, html


if __name__ == "__main__":
    import sys

    from app.db import init_db

    if len(sys.argv) != 2:
        print("Uso: python -m app.otp usuario@empresa.com")
        sys.exit(2)
    init_db()
    email = sys.argv[1].strip().lower()
    with SessionLocal() as db:
        u = db.scalar(select(User).where(User.email == email))
        if not u or not u.active:
            print(f"ERROR: no existe un usuario activo con el correo {email}")
            sys.exit(1)
        db.execute(update(LoginCode).where(LoginCode.user_id == u.id, LoginCode.used_at.is_(None))
                   .values(used_at=now_utc()))
        code = _new_code()
        db.add(LoginCode(user_id=u.id, code_hash=_hash(u.id, code), ip="consola del servidor",
                         expires_at=now_utc() + timedelta(minutes=CODE_TTL_MIN)))
        db.commit()
    print(f"Código de ingreso para {email}: {code}  (vence en {CODE_TTL_MIN} minutos)")
