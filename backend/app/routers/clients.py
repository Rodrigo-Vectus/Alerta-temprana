import re

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.db import SessionLocal
from app.models import Client, ClientContact, ClientTechnology, KevVulnerability, WatchVendor

router = APIRouter(prefix="/api", tags=["inventario"])


class ClientIn(BaseModel):
    name: str
    country: str | None = None
    sector: str | None = None
    contact_email: str | None = None


class ClientUpdate(BaseModel):
    name: str | None = None
    country: str | None = None
    sector: str | None = None
    contact_email: str | None = None
    active: bool | None = None


class WatchIn(BaseModel):
    vendor: str
    tier: int = 2


class ContactIn(BaseModel):
    name: str = ""
    email: str
    position: str | None = None


class ContactUpdate(BaseModel):
    name: str | None = None
    email: str | None = None
    position: str | None = None
    active: bool | None = None


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _email(e: str) -> str:
    e = (e or "").strip().lower()
    if not EMAIL_RE.match(e):
        raise HTTPException(400, f"Email inválido: {e or '(vacío)'}")
    return e


class TechIn(BaseModel):
    vendor: str
    product: str = ""
    version: str | None = None
    internet_exposed: bool = False


def _client(db, c):
    techs = db.scalars(select(ClientTechnology).where(ClientTechnology.client_id == c.id)).all()
    contacts = db.scalars(select(ClientContact).where(ClientContact.client_id == c.id).order_by(ClientContact.name, ClientContact.email)).all()
    return {"id": c.id, "name": c.name, "country": c.country, "sector": c.sector, "active": c.active,
            "contacts": [{"id": x.id, "name": x.name, "email": x.email, "position": x.position, "active": x.active} for x in contacts],
            "technologies": [{"id": t.id, "vendor": t.vendor, "product": t.product, "version": t.version,
                              "internet_exposed": t.internet_exposed} for t in techs]}


@router.get("/clients/recipients")
def recipients_summary():
    """Quiénes reciben las alertas automáticas: contactos activos de clientes activos."""
    with SessionLocal() as db:
        rows = db.execute(select(ClientContact.email, Client.name)
                          .join(Client, Client.id == ClientContact.client_id)
                          .where(Client.active.is_(True), ClientContact.active.is_(True))).all()
        return {"contacts": len({e for e, _ in rows}), "clients": len({c for _, c in rows})}


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


@router.patch("/clients/{client_id}")
def update_client(client_id: int, body: ClientUpdate):
    with SessionLocal() as db:
        c = db.get(Client, client_id)
        if not c:
            raise HTTPException(404, "Cliente no encontrado")
        for k, v in body.model_dump(exclude_none=True).items():
            setattr(c, k, v)
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


@router.post("/clients/{client_id}/contacts", status_code=201)
def add_contact(client_id: int, body: ContactIn):
    with SessionLocal() as db:
        c = db.get(Client, client_id)
        if not c:
            raise HTTPException(404, "Cliente no encontrado")
        db.add(ClientContact(client_id=client_id, name=body.name.strip(), email=_email(body.email),
                             position=(body.position or "").strip() or None))
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "Ese email ya está cargado para este cliente")
        return _client(db, c)


@router.patch("/clients/{client_id}/contacts/{contact_id}")
def update_contact(client_id: int, contact_id: int, body: ContactUpdate):
    with SessionLocal() as db:
        x = db.get(ClientContact, contact_id)
        if not x or x.client_id != client_id:
            raise HTTPException(404, "Contacto no encontrado")
        data = body.model_dump(exclude_none=True)
        if "email" in data:
            data["email"] = _email(data["email"])
        for k, v in data.items():
            setattr(x, k, v)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "Ese email ya está cargado para este cliente")
        return _client(db, db.get(Client, client_id))


@router.delete("/clients/{client_id}/contacts/{contact_id}", status_code=204)
def delete_contact(client_id: int, contact_id: int):
    with SessionLocal() as db:
        x = db.get(ClientContact, contact_id)
        if not x or x.client_id != client_id:
            raise HTTPException(404, "Contacto no encontrado")
        db.delete(x)
        db.commit()


@router.delete("/clients/{client_id}/technologies/{tech_id}", status_code=204)
def delete_technology(client_id: int, tech_id: int):
    with SessionLocal() as db:
        t = db.get(ClientTechnology, tech_id)
        if not t or t.client_id != client_id:
            raise HTTPException(404, "Tecnología no encontrada")
        db.delete(t)
        db.commit()


@router.delete("/clients/{client_id}", status_code=204)
def delete_client(client_id: int):
    with SessionLocal() as db:
        c = db.get(Client, client_id)
        if not c:
            raise HTTPException(404, "Cliente no encontrado")
        for t in db.scalars(select(ClientTechnology).where(ClientTechnology.client_id == client_id)).all():
            db.delete(t)
        for x in db.scalars(select(ClientContact).where(ClientContact.client_id == client_id)).all():
            db.delete(x)
        db.delete(c)
        db.commit()


@router.get("/watchlist")
def watchlist():
    with SessionLocal() as db:
        rows = db.scalars(select(WatchVendor).order_by(WatchVendor.tier, WatchVendor.vendor)).all()
        return [{"id": w.id, "vendor": w.vendor, "tier": w.tier} for w in rows]


@router.post("/watchlist", status_code=201)
def add_watch(body: WatchIn):
    if body.tier not in (1, 2):
        raise HTTPException(400, "El nivel debe ser 1 (uso masivo) o 2 (vigilado)")
    with SessionLocal() as db:
        w = WatchVendor(vendor=body.vendor.strip(), tier=body.tier)
        db.add(w)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "Ese fabricante ya está en la lista")
        return {"id": w.id, "vendor": w.vendor, "tier": w.tier}


@router.delete("/watchlist/{watch_id}", status_code=204)
def delete_watch(watch_id: int):
    with SessionLocal() as db:
        w = db.get(WatchVendor, watch_id)
        if not w:
            raise HTTPException(404, "No encontrado")
        db.delete(w)
        db.commit()


@router.get("/catalog/vendors")
def catalog_vendors(q: str = "", limit: int = Query(15, le=50)):
    """Sugerencias con los nombres exactos que usa CISA, para cargar el inventario sin errores."""
    with SessionLocal() as db:
        query = (select(KevVulnerability.vendor_project, KevVulnerability.product, func.count())
                 .group_by(KevVulnerability.vendor_project, KevVulnerability.product)
                 .order_by(func.count().desc()))
        if q.strip():
            like = f"%{q.strip()}%"
            query = query.where(KevVulnerability.vendor_project.ilike(like) | KevVulnerability.product.ilike(like))
        return [{"vendor": v, "product": p, "count": n} for v, p, n in db.execute(query.limit(limit)).all()]
