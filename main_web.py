"""
Application FastAPI pour l'interface web locale du gestionnaire de mots de passe.
"""

from __future__ import annotations

import secrets
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from password_manager.backend.api import router as api_router
from password_manager.backend.security import add_session_middleware


def create_app() -> FastAPI:
    app = FastAPI(title="Password Manager Web", docs_url=None, redoc_url=None)

    # Sécurité basique : CORS strict (même origine) et sessions
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost", "http://127.0.0.1"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    secret_key = secrets.token_urlsafe(32)
    add_session_middleware(app, secret_key=secret_key)

    # Fichiers statiques (CSS/JS)
    app.mount(
        "/static",
        StaticFiles(directory="password_manager/static"),
        name="static",
    )

    # Inclure les routes API + pages
    app.include_router(api_router)

    @app.middleware("http")
    async def local_only_middleware(request: Request, call_next) -> Any:
        """
        Empêche l'accès depuis l'extérieur de la machine locale.
        """
        client_host = request.client.host if request.client else None
        if client_host not in ("127.0.0.1", "::1", "localhost"):
            from fastapi import HTTPException, status

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Accès autorisé uniquement depuis localhost.",
            )
        response = await call_next(request)
        return response

    return app


app = create_app()

