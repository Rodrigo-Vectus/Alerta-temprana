from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import text
from app.db import engine

app = FastAPI(
    title="Vectus SAT - Alerta Temprana",
    version="0.1.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

@app.get("/api/health")
def health():
    try:
        with engine.connect() as conn:
            version = conn.execute(text("select version()")).scalar()
        return {"status": "ok", "db": "ok", "postgres": version.split(",")[0]}
    except Exception as exc:
        return JSONResponse(status_code=503, content={"status": "degraded", "db": str(exc)})
