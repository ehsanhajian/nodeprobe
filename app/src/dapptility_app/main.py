from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from dapptility_app.database import init_db
from dapptility_app.routes import admin, public
from dapptility_app.services import store
from dapptility_app.database import SessionLocal


def create_app() -> FastAPI:
    init_db()
    app = FastAPI(title="Dapptility", version="0.1.0")
    app.include_router(admin.router)
    app.include_router(public.router)

    @app.get("/")
    def root():
        return RedirectResponse("/admin")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.on_event("startup")
    def purge_expired_evidence():
        db = SessionLocal()
        try:
            store.purge_expired_raw(db)
        finally:
            db.close()

    return app


app = create_app()
