from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.auth import get_current_user, require_role
from app.comms import mailer
from app.db import SessionLocal
from app.models import User
from app.settings import get_settings, save_settings

router = APIRouter(prefix="/api/settings", tags=["configuración"])


class SettingsIn(BaseModel):
    auto_send: bool | None = None
    delay_minutes: int | None = None
    min_score: int | None = None
    soc_emails: list[str] | None = None
    attach_docx: bool | None = None
    public_url: str | None = None


@router.get("")
def read_settings(user: User = Depends(get_current_user)):
    with SessionLocal() as db:
        return {**get_settings(db), "mail": mailer.public_status()}


@router.put("")
def update_settings(body: SettingsIn, user: User = Depends(require_role("admin"))):
    data = body.model_dump(exclude_none=True)
    if "delay_minutes" in data and not 0 <= data["delay_minutes"] <= 1440:
        raise HTTPException(400, "La ventana debe estar entre 0 y 1440 minutos")
    if "min_score" in data and not 0 <= data["min_score"] <= 100:
        raise HTTPException(400, "El umbral debe estar entre 0 y 100")
    if "soc_emails" in data:
        data["soc_emails"] = [e.strip().lower() for e in data["soc_emails"] if e.strip()]
    if "public_url" in data:
        data["public_url"] = data["public_url"].strip().rstrip("/")
    with SessionLocal() as db:
        return {**save_settings(db, data, user.email), "mail": mailer.public_status()}
