from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from dapptility_app.database import SessionLocal, init_db
from dapptility_app.routes import admin, public
from dapptility_app.services import store
from dapptility_app.services.scheduler import start_scheduler, stop_scheduler


@asynccontextmanager
async def lifespan(app: FastAPI):
    start_scheduler()
    db = SessionLocal()
    try:
        store.purge_expired_raw(db)
    finally:
        db.close()
    yield
    stop_scheduler()


def create_app() -> FastAPI:
    init_db()
    app = FastAPI(title="Dapptility", version="0.1.0", lifespan=lifespan)
    app.include_router(admin.router)
    app.include_router(public.router)

    @app.get("/")
    def root():
        return RedirectResponse("/admin")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


app = create_app()
