from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.db import SessionLocal
from app.models import Client, ClientTechnology, WatchVendor

router = APIRouter(prefix="/api", tags=["inventario"])


class ClientIn(BaseModel):
    name: str
    country: str | None = None
    sector: str | None = None
    contact_email: str | None = None


class TechIn(BaseModel):
    vendor: str
    product: str = ""
    version: str | None = None
    internet_exposed: bool = False


def _client(db, c):
    techs = db.scalars(select(ClientTechnology).where(ClientTechnology.client_id == c.id)).all()
    return {"id": c.id, "name": c.name, "country": c.country, "sector": c.sector,
            "contact_email": c.contact_email, "active": c.active,
            "technologies": [{"id": t.id, "vendor": t.vendor, "product": t.product, "version": t.version,
                              "internet_exposed": t.internet_exposed} for t in techs]}


@router.get("/clients")
def list_clients():
    with SessionLocal() as db:
        return [_client(db, c) for c in db.scalars(select(Client).order_by(Client.name)).all()]


@router.post("/clients", status_code=201)
def create_client(body: ClientIn):
    with SessionLocal() as db:
        c = Client(**body.model_dump())
        db.add(c)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "Ya existe un cliente con ese nombre")
        return _client(db, c)


@router.post("/clients/{client_id}/technologies", status_code=201)
def add_technologies(client_id: int, body: list[TechIn]):
    with SessionLocal() as db:
        c = db.get(Client, client_id)
        if not c:
            raise HTTPException(404, "Cliente no encontrado")
        for t in body:
            db.add(ClientTechnology(client_id=client_id, **t.model_dump()))
        db.commit()
        return _client(db, c)


@router.delete("/clients/{client_id}", status_code=204)
def delete_client(client_id: int):
    with SessionLocal() as db:
        c = db.get(Client, client_id)
        if not c:
            raise HTTPException(404, "Cliente no encontrado")
        for t in db.scalars(select(ClientTechnology).where(ClientTechnology.client_id == client_id)).all():
            db.delete(t)
        db.delete(c)
        db.commit()


@router.get("/watchlist")
def watchlist():
    with SessionLocal() as db:
        rows = db.scalars(select(WatchVendor).order_by(WatchVendor.tier, WatchVendor.vendor)).all()
        return [{"id": w.id, "vendor": w.vendor, "tier": w.tier} for w in rows]
