"""AI-NIDR backend: REST API, live events and the detection pipeline."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .config import get_settings
from .database import Base, SessionLocal, engine
from .engine.pipeline import Pipeline
from .response.engine import ResponseEngine
from .response.firewall import DryRunFirewall, Firewall, NftablesSshFirewall
from .routers import admin, auth, incidents, ingest, responses, ws

log = logging.getLogger("ainidr")


def make_firewall() -> Firewall:
    settings = get_settings()
    hosts = [h.strip() for h in settings.firewall_hosts.split(",") if h.strip()]
    if settings.firewall_mode == "ssh" and hosts and settings.firewall_ssh_key:
        return NftablesSshFirewall(hosts, settings.firewall_ssh_key)
    return DryRunFirewall()


def create_app(firewall: Firewall | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        Base.metadata.create_all(engine)
        app.state.pipeline = Pipeline(ResponseEngine(firewall or make_firewall()))
        with SessionLocal() as db:
            app.state.pipeline.load_models(db)
        if app.state.pipeline.main is None:
            log.warning("No detection model is active. Run: python -m app.cli bootstrap-model")
        yield

    app = FastAPI(title="AI-NIDR", version="0.1.0", lifespan=lifespan)
    for router in (auth.router, ingest.router, incidents.router, responses.router, admin.router, ws.router):
        app.include_router(router, prefix="/api/v1")

    @app.get("/health")
    def health():
        pipeline = app.state.pipeline
        return {"status": "ok", "main_model": pipeline.main.version if pipeline.main else None,
                "anomaly_model": pipeline.anomaly.version if pipeline.anomaly else None,
                "firewall": type(pipeline.responder.firewall).__name__}

    return app


app = create_app()
