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


from sqlalchemy import Float  # noqa: E402


class CveEnrichment(Base):
    __tablename__ = "cve_enrichment"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_version: Mapped[str | None] = mapped_column(String(8))
    cvss_severity: Mapped[str | None] = mapped_column(String(16))
    cvss_vector: Mapped[str | None] = mapped_column(String(255))
    epss: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    nvd_published: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    nvd_status: Mapped[str | None] = mapped_column(String(32))
    cwes: Mapped[list] = mapped_column(JSONB, default=list)
    ref_urls: Mapped[list] = mapped_column(JSONB, default=list)
    cpes: Mapped[list] = mapped_column(JSONB, default=list)
    nvd_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    epss_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    fetched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class WatchVendor(Base):
    __tablename__ = "watch_vendors"

    id: Mapped[int] = mapped_column(primary_key=True)
    vendor: Mapped[str] = mapped_column(String(255), unique=True)
    tier: Mapped[int] = mapped_column(Integer, default=2)       # 1 = uso masivo, 2 = vigilado


class Client(Base):
    __tablename__ = "clients"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    country: Mapped[str | None] = mapped_column(String(64))
    sector: Mapped[str | None] = mapped_column(String(128))
    contact_email: Mapped[str | None] = mapped_column(String(255))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ClientTechnology(Base):
    __tablename__ = "client_technologies"

    id: Mapped[int] = mapped_column(primary_key=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id", ondelete="CASCADE"), index=True)
    vendor: Mapped[str] = mapped_column(String(255))
    product: Mapped[str] = mapped_column(String(255), default="")   # vacío o "*" = todo el fabricante
    version: Mapped[str | None] = mapped_column(String(128))
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str | None] = mapped_column(String(32), unique=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("kev_vulnerabilities.cve_id"), unique=True)
    score: Mapped[int] = mapped_column(Integer)
    level: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(24), index=True)
    breakdown: Mapped[list] = mapped_column(JSONB, default=list)
    matched_clients: Mapped[list] = mapped_column(JSONB, default=list)
    history: Mapped[list] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(255), default="")
    role: Mapped[str] = mapped_column(String(16), default="lector")      # admin | analista | lector
    password_hash: Mapped[str] = mapped_column(String(255))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(Integer, index=True)
    user_email: Mapped[str | None] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(128), index=True)
    method: Mapped[str | None] = mapped_column(String(8))
    path: Mapped[str | None] = mapped_column(String(255))
    status_code: Mapped[int | None] = mapped_column(Integer)
    ip: Mapped[str | None] = mapped_column(String(64))
    detail: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)


class Communication(Base):
    """Comunicado preventivo asociado a una alerta: newsletter (cuerpo del mail) + informe adjunto."""
    __tablename__ = "communications"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str | None] = mapped_column(String(32), unique=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(16), default="borrador")     # borrador | aprobado | enviado
    content: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_by: Mapped[str | None] = mapped_column(String(255))
    updated_by: Mapped[str | None] = mapped_column(String(255))
    approved_by: Mapped[str | None] = mapped_column(String(255))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sends: Mapped[list] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
