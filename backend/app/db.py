import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

engine = create_engine(os.environ["DATABASE_URL"], pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

def init_db():
    """Crea las tablas. El advisory lock evita que backend y worker choquen al arrancar juntos."""
    from app.models import Base
    with engine.begin() as conn:
        conn.execute(text("SELECT pg_advisory_xact_lock(424242)"))
        Base.metadata.create_all(conn)
        # Migraciones simples: columnas agregadas a tablas que ya existían en versiones anteriores
        for stmt in MIGRATIONS:
            conn.execute(text(stmt))


MIGRATIONS = [
    "ALTER TABLE communications ADD COLUMN IF NOT EXISTS scheduled_at TIMESTAMPTZ",
    "ALTER TABLE communications ADD COLUMN IF NOT EXISTS auto BOOLEAN DEFAULT FALSE",
    "CREATE INDEX IF NOT EXISTS ix_communications_scheduled_at ON communications (scheduled_at)",
    # Los contactos cargados en el campo único de la versión anterior pasan a la tabla de contactos
    """INSERT INTO client_contacts (client_id, name, email, active, created_at)
       SELECT id, '', lower(trim(contact_email)), TRUE, now() FROM clients
       WHERE contact_email IS NOT NULL AND trim(contact_email) <> ''
       ON CONFLICT (client_id, email) DO NOTHING""",
    "UPDATE clients SET contact_email = NULL WHERE contact_email IS NOT NULL",
    # Ingreso por código (OTP): ya no hay contraseñas que cambiar
    "UPDATE users SET must_change_password = FALSE WHERE must_change_password",
    # Playbook por mail al SOC: los casos que ya existían se marcan como notificados (no se reenvían en masa)
    """DO $$ BEGIN
         IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'use_cases' AND column_name = 'soc_notified_at') THEN
           ALTER TABLE use_cases ADD COLUMN soc_notified_at TIMESTAMPTZ;
           UPDATE use_cases SET soc_notified_at = now();
         END IF;
       END $$""",
]
