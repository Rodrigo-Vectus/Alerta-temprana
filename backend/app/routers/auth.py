from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select

from app.auth import (DUMMY_HASH, JWT_EXPIRE_HOURS, LOCK_MINUTES, MAX_FAILED, audit, create_token,
                      get_current_user, hash_password, now_utc, validate_password, verify_password)
from app.db import SessionLocal
from app.models import User

router = APIRouter(prefix="/api/auth", tags=["autenticación"])


class LoginIn(BaseModel):
    email: str
    password: str


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str


def me_dict(u: User):
    return {"id": u.id, "email": u.email, "full_name": u.full_name, "role": u.role,
            "must_change_password": u.must_change_password, "last_login_at": u.last_login_at}


@router.post("/login")
def login(body: LoginIn, request: Request):
    email, now = body.email.strip().lower(), now_utc()
    with SessionLocal() as db:
        u = db.scalar(select(User).where(User.email == email))
        if u and u.locked_until and u.locked_until > now:
            audit("login_bloqueado", request=request, status_code=423, email=email)
            raise HTTPException(423, f"Usuario bloqueado temporalmente ({LOCK_MINUTES} min) por intentos fallidos")
        ok = verify_password(body.password, u.password_hash if u else DUMMY_HASH)
        if not u or not u.active or not ok:
            if u:
                u.failed_attempts = (u.failed_attempts or 0) + 1
                if u.failed_attempts >= MAX_FAILED:
                    u.locked_until, u.failed_attempts = now + timedelta(minutes=LOCK_MINUTES), 0
                db.commit()
            audit("login_fallido", request=request, status_code=401, email=email)
            raise HTTPException(401, "Credenciales inválidas")
        u.failed_attempts, u.locked_until, u.last_login_at = 0, None, now
        db.commit()
        audit("login_ok", user=u, request=request, status_code=200)
        return {"access_token": create_token(u), "token_type": "bearer",
                "expires_in": JWT_EXPIRE_HOURS * 3600, "user": me_dict(u)}


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return me_dict(user)


@router.post("/change-password")
def change_password(body: ChangePasswordIn, user: User = Depends(get_current_user)):
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(400, "La contraseña actual no es correcta")
    if body.new_password == body.current_password:
        raise HTTPException(400, "La nueva contraseña debe ser distinta de la actual")
    validate_password(body.new_password)
    with SessionLocal() as db:
        u = db.get(User, user.id)
        u.password_hash, u.must_change_password = hash_password(body.new_password), False
        db.commit()
    return {"ok": True}
