import logging
import re

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select

from app import otp
from app.auth import JWT_EXPIRE_HOURS, audit, client_ip, create_token, get_current_user, now_utc, validate_email
from app.comms import mailer
from app.db import SessionLocal
from app.models import User
from app.settings import get_settings

router = APIRouter(prefix="/api/auth", tags=["autenticación"])
log = logging.getLogger("auth")

GENERIC = ("Si el correo está registrado en la plataforma, te enviamos un código de 6 dígitos. "
           "Revisá también la carpeta de spam.")


class CodeRequestIn(BaseModel):
    email: str


class CodeVerifyIn(BaseModel):
    email: str
    code: str


def me_dict(u: User):
    return {"id": u.id, "email": u.email, "full_name": u.full_name, "role": u.role,
            "must_change_password": False, "last_login_at": u.last_login_at}


def _send_code(user_id: int, code: str, ip: str | None, request_path: str):
    with SessionLocal() as db:
        u = db.get(User, user_id)
        public_url = get_settings(db).get("public_url", "")
    subject, text, html = otp.email_body(u, code, ip, public_url)
    try:
        mailer.send_simple(u.email, subject, text, html)
        audit("otp_enviado", user=u, status_code=200, ip_origen=ip)
    except Exception as e:  # noqa: BLE001
        log.error("No se pudo enviar el código a %s: %s", u.email, e)
        audit("otp_error_envio", user=u, status_code=500, error=str(e)[:300])


@router.post("/request-code")
def request_code(body: CodeRequestIn, request: Request, tasks: BackgroundTasks):
    """Siempre responde lo mismo: no revela si el correo tiene usuario."""
    email = validate_email(body.email)
    ip = client_ip(request)
    with SessionLocal() as db:
        u = db.scalar(select(User).where(User.email == email))
        if u and u.active:
            code = otp.issue(db, u, ip)
            if code:
                tasks.add_task(_send_code, u.id, code, ip, request.url.path)
                audit("otp_solicitado", user=u, request=request, status_code=200)
            else:
                audit("otp_limite", user=u, request=request, status_code=200)
        else:
            audit("otp_correo_desconocido", request=request, status_code=200, email=email)
    return {"ok": True, "message": GENERIC, "resend_after": otp.RESEND_SECONDS, "ttl_minutes": otp.CODE_TTL_MIN}


@router.post("/verify-code")
def verify_code(body: CodeVerifyIn, request: Request):
    email = validate_email(body.email)
    code = re.sub(r"\D", "", body.code or "")
    if len(code) != 6:
        raise HTTPException(400, "El código tiene 6 dígitos")
    with SessionLocal() as db:
        u = db.scalar(select(User).where(User.email == email))
        result = otp.verify(db, u, code) if u and u.active else "invalid"
        if result == "too_many":
            audit("otp_bloqueado", user=u, request=request, status_code=401)
            raise HTTPException(401, "Demasiados intentos con este código. Pedí uno nuevo.")
        if result != "ok":
            audit("login_fallido", user=u, request=request, status_code=401, email=email)
            raise HTTPException(401, "Código incorrecto o vencido")
        u.last_login_at, u.failed_attempts, u.locked_until = now_utc(), 0, None
        db.commit()
        audit("login_ok", user=u, request=request, status_code=200, metodo="codigo_mail")
        return {"access_token": create_token(u), "token_type": "bearer",
                "expires_in": JWT_EXPIRE_HOURS * 3600, "user": me_dict(u)}


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return me_dict(user)
