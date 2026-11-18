import os
import re
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import func, select

from app.db import SessionLocal
from app.models import AuditLog, User

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALG = "HS256"
JWT_EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "8"))
ROLES = ("admin", "analista", "lector")
WRITE_ROLES = ("admin", "analista")
MAX_FAILED, LOCK_MINUTES = 5, 15
READ_ONLY_POSTS = {"/api/communications/preview"}   # POST que no modifican datos
PASSWORD_CHANGE_PATHS = {"/api/auth/me", "/api/auth/change-password"}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

bearer = HTTPBearer(auto_error=False)


def now_utc():
    return datetime.now(timezone.utc)


def hash_password(p: str) -> str:
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(p: str, h: str) -> bool:
    try:
        return bcrypt.checkpw(p.encode(), h.encode())
    except ValueError:
        return False


DUMMY_HASH = hash_password("dummy-password-000")


def validate_password(p: str):
    if len(p) < 10 or not re.search(r"[A-Za-z]", p) or not re.search(r"\d", p):
        raise HTTPException(400, "La contraseña debe tener al menos 10 caracteres, con letras y números")


def validate_email(e: str) -> str:
    e = (e or "").strip().lower()
    if not EMAIL_RE.match(e):
        raise HTTPException(400, "Email inválido")
    return e


def create_token(user: User) -> str:
    now = now_utc()
    payload = {"sub": str(user.id), "role": user.role, "iat": now,
               "exp": now + timedelta(hours=JWT_EXPIRE_HOURS)}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def decode_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.PyJWTError:
        return None


def client_ip(request: Request | None):
    if request is None:
        return None
    return request.headers.get("x-real-ip") or (request.client.host if request.client else None)


def audit(action: str, user: User | None = None, request: Request | None = None,
          status_code: int | None = None, **detail):
    with SessionLocal() as db:
        db.add(AuditLog(
            user_id=user.id if user else None,
            user_email=user.email if user else detail.get("email"),
            action=action,
            method=request.method if request else None,
            path=request.url.path if request else None,
            status_code=status_code, ip=client_ip(request), detail=detail,
        ))
        db.commit()


def audit_request(user_id: int | None, request: Request, status_code: int):
    with SessionLocal() as db:
        email = db.scalar(select(User.email).where(User.id == user_id)) if user_id else None
        db.add(AuditLog(user_id=user_id, user_email=email,
                        action=f"{request.method} {request.url.path}",
                        method=request.method, path=request.url.path,
                        status_code=status_code, ip=client_ip(request),
                        detail={"query": str(request.url.query)} if request.url.query else {}))
        db.commit()


def get_current_user(request: Request,
                     cred: HTTPAuthorizationCredentials | None = Depends(bearer)) -> User:
    if not cred:
        raise HTTPException(401, "No autenticado", headers={"WWW-Authenticate": "Bearer"})
    payload = decode_token(cred.credentials)
    if not payload:
        raise HTTPException(401, "Token inválido o vencido", headers={"WWW-Authenticate": "Bearer"})
    with SessionLocal() as db:
        user = db.get(User, int(payload["sub"]))
    if not user or not user.active:
        raise HTTPException(401, "Usuario inexistente o inactivo")
    if user.must_change_password and request.url.path not in PASSWORD_CHANGE_PATHS:
        raise HTTPException(403, "Debe cambiar la contraseña antes de continuar")
    return user


def require_role(*roles):
    def dep(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(403, "Permisos insuficientes")
        return user
    return dep


def write_guard(request: Request, user: User = Depends(get_current_user)) -> User:
    if (request.method not in ("GET", "HEAD", "OPTIONS") and user.role not in WRITE_ROLES
            and request.url.path not in READ_ONLY_POSTS):
        raise HTTPException(403, "Su rol es de solo lectura")
    return user


def bootstrap_admin():
    email = os.getenv("ADMIN_EMAIL", "").strip().lower()
    pwd = os.getenv("ADMIN_INITIAL_PASSWORD", "").strip()
    if not email or not pwd:
        return
    with SessionLocal() as db:
        if db.scalar(select(func.count()).select_from(User)):
            return
        db.add(User(email=email, full_name="Administrador", role="admin",
                    password_hash=hash_password(pwd), must_change_password=True))
        db.commit()
