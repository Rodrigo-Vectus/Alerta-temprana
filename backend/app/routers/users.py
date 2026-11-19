from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.auth import ROLES, get_current_user, now_utc, require_role, unusable_password, validate_email
from app.db import SessionLocal
from app.models import AuditLog, User

router = APIRouter(prefix="/api", tags=["usuarios"], dependencies=[Depends(require_role("admin"))])


class UserIn(BaseModel):
    email: str
    full_name: str = ""
    role: str = "lector"


class UserUpdate(BaseModel):
    full_name: str | None = None
    role: str | None = None
    active: bool | None = None


def _u(u: User):
    now = now_utc()
    return {"id": u.id, "email": u.email, "full_name": u.full_name, "role": u.role, "active": u.active,
            "locked": bool(u.locked_until and u.locked_until > now),
            "last_login_at": u.last_login_at, "created_at": u.created_at}


def _check_role(role):
    if role not in ROLES:
        raise HTTPException(400, f"Rol inválido. Opciones: {', '.join(ROLES)}")


@router.get("/users")
def list_users():
    with SessionLocal() as db:
        return [_u(u) for u in db.scalars(select(User).order_by(User.email)).all()]


@router.post("/users", status_code=201)
def create_user(body: UserIn):
    email = validate_email(body.email)
    _check_role(body.role)
    with SessionLocal() as db:
        u = User(email=email, full_name=body.full_name, role=body.role,
                 password_hash=unusable_password(), must_change_password=False)
        db.add(u)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "Ya existe un usuario con ese email")
        return _u(u)


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: UserUpdate, current: User = Depends(get_current_user)):
    with SessionLocal() as db:
        u = db.get(User, user_id)
        if not u:
            raise HTTPException(404, "Usuario no encontrado")
        if u.id == current.id and ((body.role and body.role != "admin") or body.active is False):
            raise HTTPException(400, "No podés quitarte el rol admin ni desactivarte a vos mismo")
        if body.full_name is not None:
            u.full_name = body.full_name
        if body.role is not None:
            _check_role(body.role)
            u.role = body.role
        if body.active is not None:
            u.active = body.active
        db.commit()
        return _u(u)


@router.get("/audit")
def audit_log(limit: int = Query(100, le=1000), user_id: int | None = None, action: str | None = None):
    with SessionLocal() as db:
        q = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)
        if user_id:
            q = q.where(AuditLog.user_id == user_id)
        if action:
            q = q.where(AuditLog.action.ilike(f"%{action}%"))
        return [{"id": a.id, "created_at": a.created_at, "user_email": a.user_email, "action": a.action,
                 "status_code": a.status_code, "ip": a.ip, "detail": a.detail}
                for a in db.scalars(q).all()]
