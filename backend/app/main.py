import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text

from .config import get_settings
from .db import get_db
from .routers import admin, devices, incidents, reputation, rules

log = logging.getLogger("sentinel")

app = FastAPI(
    title="Sentinel Mobile SOC API",
    version="0.1.0",
    description="Optional backend: reputation proxy (keeps provider keys off devices), signed rule distribution, opt-in incident sync.",
)


@app.middleware("http")
async def hardening(request: Request, call_next):
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > get_settings().max_body_bytes:
        return JSONResponse({"detail": "request too large"}, status_code=413)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


@app.exception_handler(RequestValidationError)
async def validation_error(_: Request, exc: RequestValidationError):
    # Field names only: never echo submitted values (they may be sensitive URLs).
    fields = [".".join(str(p) for p in e["loc"]) for e in exc.errors()]
    return JSONResponse({"detail": "invalid request", "fields": fields}, status_code=422)


@app.exception_handler(Exception)
async def unhandled(_: Request, exc: Exception):
    log.exception("unhandled error: %s", type(exc).__name__)
    return JSONResponse({"detail": "internal error"}, status_code=500)


@app.get("/health", tags=["health"])
def health():
    db = next(get_db())
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok"}
    finally:
        db.close()


for r in (devices.router, reputation.router, rules.router, incidents.router, admin.router):
    app.include_router(r)
