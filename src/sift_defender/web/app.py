"""FastAPI application — serves dashboard and runs investigations."""

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from sift_defender.web.routes import api_router, ws_router, pages_router


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="AEGIS-IR",
        description="Autonomous Evidence-Guided Investigation System for Incident Response",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )

    # CORS — allow dashboard on different domains (Cloud Run, custom domain)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Restrict in production to specific domains
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Enterprise: Audit middleware (logs every API request automatically)
    try:
        from sift_defender.enterprise.audit.middleware import AuditMiddleware
        from sift_defender.enterprise.audit.service import AuditLogService

        app.add_middleware(AuditMiddleware, audit_service=AuditLogService())
    except ImportError:
        pass  # Enterprise module not installed

    # Templates
    templates_dir = Path(__file__).parent / "templates"
    templates_dir.mkdir(exist_ok=True)

    # Static files
    static_dir = Path(__file__).parent / "static"
    static_dir.mkdir(exist_ok=True)
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Core Routers
    app.include_router(pages_router)
    app.include_router(api_router, prefix="/api")
    app.include_router(ws_router)

    # Enterprise Routers
    try:
        from sift_defender.enterprise.auth.endpoints import router as auth_router
        from sift_defender.enterprise.observability.routes import observability_router

        app.include_router(auth_router)
        app.include_router(observability_router)
    except ImportError:
        pass  # Enterprise module not installed

    return app
