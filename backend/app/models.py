from datetime import date, datetime
from sqlalchemy import String, Text, Date, DateTime, Integer, Boolean, ForeignKey, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class KevVulnerability(Base):
    __tablename__ = "kev_vulnerabilities"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    vendor_project: Mapped[str] = mapped_column(String(255), index=True)
    product: Mapped[str] = mapped_column(String(255), index=True)
    vulnerability_name: Mapped[str] = mapped_column(Text)
    short_description: Mapped[str] = mapped_column(Text)
    required_action: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)
    known_ransomware: Mapped[str | None] = mapped_column(String(32))
    cwes: Mapped[list] = mapped_column(JSONB, default=list)
    date_added: Mapped[date | None] = mapped_column(Date, index=True)
    due_date: Mapped[date | None] = mapped_column(Date)
    content_hash: Mapped[str] = mapped_column(String(64))
    raw: Mapped[dict] = mapped_column(JSONB)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    change_count: Mapped[int] = mapped_column(Integer, default=0)


class KevEvent(Base):
    """Cola de cambios detectados. La Fase 3 (puntaje) consume los processed=False."""
    __tablename__ = "kev_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("kev_vulnerabilities.cve_id"), index=True)
    event_type: Mapped[str] = mapped_column(String(16))          # new | updated
    changed_fields: Mapped[dict] = mapped_column(JSONB, default=dict)
    processed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class CollectorRun(Base):
    __tablename__ = "collector_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(32), default="cisa_kev", index=True)
    status: Mapped[str] = mapped_column(String(16))               # running | ok | baseline | unchanged | error
    catalog_version: Mapped[str | None] = mapped_column(String(32))
    total: Mapped[int] = mapped_column(Integer, default=0)
    new_count: Mapped[int] = mapped_column(Integer, default=0)
    updated_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
