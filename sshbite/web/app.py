"""FastAPI application: security headers, JSON errors, the API router and the built frontend (spec 5, 8.1)."""

from __future__ import annotations

import sqlite3
from importlib import resources
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from .. import db as dbm
from .auth import Guard
from .data import Views

CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
       "frame-ancestors 'none'")
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, **extra):
        self.status = status
        self.code = code
        self.message = message
        self.extra = extra


def error_response(status: int, code: str, message: str, **extra) -> JSONResponse:
    body = {"error": {"code": code, "message": message, **extra}}
    return JSONResponse(body, status_code=status)


def static_dir() -> Path:
    return Path(str(resources.files("sshbite.web").joinpath("static")))


def create_app(database: str, session_hours: float = 8, tls: bool = False, guard: Guard | None = None) -> FastAPI:
    # migrate once at start (writes a backup before migrating an existing DB, spec 8.2)
    conn = dbm.connect(database)
    conn.close()

    app = FastAPI(title="SSHBITE", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.database = database
    app.state.session_hours = session_hours
    app.state.tls = tls
    app.state.guard = guard or Guard()
    app.state.views = Views()

    @app.middleware("http")
    async def headers(request: Request, call_next):
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        if tls:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        return response

    @app.exception_handler(ApiError)
    async def api_error(_request: Request, exc: ApiError):
        return error_response(exc.status, exc.code, exc.message, **exc.extra)

    @app.exception_handler(RequestValidationError)
    async def bad_request(_request: Request, exc: RequestValidationError):
        errs = exc.errors()
        msg = "invalid request"
        if errs:
            e = errs[0]
            loc = ".".join(str(x) for x in e.get("loc", ())[1:]) or "request"
            msg = f"{loc}: {e.get('msg', 'invalid')}"
        return error_response(400, "bad_request", msg)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        if request.url.path.startswith("/api/") or request.url.path == "/api":
            code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "http_error")
            return error_response(exc.status_code, code, str(exc.detail))
        return Response(str(exc.detail), status_code=exc.status_code, media_type="text/plain")

    @app.exception_handler(sqlite3.OperationalError)
    async def db_error(_request: Request, exc: sqlite3.OperationalError):
        return error_response(503, "database_unavailable", f"database error: {exc}")

    from .api import router

    app.include_router(router, prefix="/api")

    sdir = static_dir()

    @app.get("/{path:path}", include_in_schema=False)
    async def frontend(path: str):
        if path.startswith("api/") or path == "api":
            return error_response(404, "not_found", "no such endpoint")
        if path:
            f = (sdir / path).resolve()
            try:
                f.relative_to(sdir.resolve())
            except ValueError:
                return Response("not found", status_code=404, media_type="text/plain")
            if f.is_file():
                headers = {"Cache-Control": "public, max-age=31536000, immutable"} if path.startswith(
                    ("assets/", "fonts/")) else {}
                return FileResponse(f, headers=headers)
            if path.startswith(("assets/", "fonts/")) or "." in path.rsplit("/", 1)[-1]:
                return Response("not found", status_code=404, media_type="text/plain")
        index = sdir / "index.html"
        if not index.is_file():
            return Response("SSHBITE frontend is not built. Run `npm ci && npm run build` in frontend/.",
                            status_code=503, media_type="text/plain")
        return FileResponse(index, headers={"Cache-Control": "no-cache"})

    return app
