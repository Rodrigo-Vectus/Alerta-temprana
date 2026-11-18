from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.auth import audit_request, bootstrap_admin, decode_token, write_guard
from app.db import engine, init_db
from app.routers import alerts, auth as auth_router, clients, communications, kev, settings as settings_router, users


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    bootstrap_admin()
    yield


app = FastAPI(title="Vectus SAT - Alerta Temprana", version="0.7.0",
              docs_url="/api/docs", openapi_url="/api/openapi.json", lifespan=lifespan)

AUDIT_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
AUDIT_SKIP = {"/api/auth/login", "/api/communications/preview"}  # login se audita adentro; preview no modifica nada


@app.middleware("http")
async def audit_writes(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path
    if request.method in AUDIT_METHODS and path.startswith("/api/") and path not in AUDIT_SKIP:
        uid = None
        authz = request.headers.get("authorization", "")
        if authz.lower().startswith("bearer "):
            payload = decode_token(authz[7:])
            uid = int(payload["sub"]) if payload else None
        try:
            await run_in_threadpool(audit_request, uid, request, response.status_code)
        except Exception:
            pass
    return response


@app.get("/api/health")
def health():
    try:
        with engine.connect() as conn:
            version = conn.execute(text("select version()")).scalar()
        return {"status": "ok", "db": "ok", "postgres": version.split(",")[0]}
    except Exception as exc:
        return JSONResponse(status_code=503, content={"status": "degraded", "db": str(exc)})


guarded = [Depends(write_guard)]
app.include_router(auth_router.router)
app.include_router(users.router)
app.include_router(settings_router.router)
app.include_router(kev.router, dependencies=guarded)
app.include_router(alerts.router, dependencies=guarded)
app.include_router(clients.router, dependencies=guarded)
app.include_router(communications.router, dependencies=guarded)
