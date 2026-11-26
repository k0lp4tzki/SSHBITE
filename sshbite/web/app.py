"""FastAPI application: security headers, JSON errors, the API router and the built frontend (spec 5, 8.1)."""

from __future__ import annotations

import ipaddress
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


MAX_API_BODY = 64 * 1024


class BodyLimit:
    """ASGI middleware: request bodies on /api larger than MAX_API_BODY get 413 (declared or streamed)."""

    def __init__(self, app, limit: int = MAX_API_BODY):
        self.app = app
        self.limit = limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not (scope["path"] == "/api" or scope["path"].startswith("/api/")):
            return await self.app(scope, receive, send)
        for k, v in scope.get("headers", []):
            if k == b"content-length":
                try:
                    too_big = int(v) > self.limit
                except ValueError:
                    too_big = True
                if too_big:
                    return await self._reject(scope, receive, send)
        if any(k == b"content-length" for k, _ in scope.get("headers", [])):
            return await self.app(scope, receive, send)
        # streamed (chunked) body: read it up to the limit first, then replay it to the app
        chunks: list[bytes] = []
        seen = 0
        while True:
            msg = await receive()
            if msg["type"] != "http.request":
                return
            chunks.append(msg.get("body", b""))
            seen += len(chunks[-1])
            if seen > self.limit:
                return await self._reject(scope, receive, send)
            if not msg.get("more_body", False):
                break
        body = b"".join(chunks)
        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)

    async def _reject(self, scope, receive, send):
        resp = error_response(413, "too_large", f"request body larger than {self.limit // 1024} KiB")
        for k, v in SECURITY_HEADERS.items():
            resp.headers.setdefault(k, v)
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Connection"] = "close"
        await resp(scope, receive, send)


def create_app(database: str, session_hours: float = 8, tls: bool = False, guard: Guard | None = None,
               secure_cookie: bool = False, trusted_proxies: list[str] | None = None) -> FastAPI:
    # migrate once at start (writes a backup before migrating an existing DB, spec 8.2)
    conn = dbm.connect(database)
    conn.close()

    app = FastAPI(title="SSHBITE", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.database = database
    app.state.session_hours = session_hours
    app.state.tls = tls
    app.state.secure_cookie = bool(tls or secure_cookie)
    app.state.trusted_proxies = [ipaddress.ip_network(p, strict=False) for p in (trusted_proxies or [])]
    app.state.guard = guard or Guard()
    app.state.views = Views()
    app.state.views.warm(database)   # the newest scans' heatmap views, off the first request (assessment §1)

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

    app.add_middleware(BodyLimit)
    return app


def client_ip(request: Request) -> str:
    """The client address for the per-IP limit. X-Forwarded-For is used only when the peer is a trusted proxy,
    and then only its last hop (the address that proxy itself saw); otherwise the header is ignored."""
    peer = request.client.host if request.client else "?"
    trusted = getattr(request.app.state, "trusted_proxies", None)
    if not trusted:
        return peer
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    if not any(peer_ip in net for net in trusted):
        return peer
    values = request.headers.getlist("x-forwarded-for")
    hops = [h.strip() for h in ",".join(values).split(",") if h.strip()]
    if not hops:
        return peer
    last = hops[-1]
    try:
        return str(ipaddress.ip_address(last.strip("[]")))
    except ValueError:
        return peer
