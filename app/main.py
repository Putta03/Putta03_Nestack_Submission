"""Application factory, middleware, and health check."""

import logging
import re
import secrets
import time
import uuid

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app import db
from app.config import Settings
from app.errors import register_error_handlers
from app.routes_auth import router as auth_router
from app.routes_records import router as records_router
from app.security import hash_password

logger = logging.getLogger("nestack")

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")


class PayloadTooLarge(HTTPException):
    """Raised from receive(); FastAPI re-raises HTTPException from body parsing."""

    def __init__(self, max_bytes: int) -> None:
        super().__init__(
            status_code=400,
            detail=f"Request body must not exceed {max_bytes} bytes.",
        )
        self.code = "payload_too_large"


class BodySizeLimitMiddleware:
    """Reject oversized bodies with 400 even when Content-Length is absent."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = Headers(scope=scope).get("content-length")
        if declared is not None:
            try:
                too_large = int(declared) > self.max_bytes
            except ValueError:
                too_large = True
            if too_large:
                await self._reject(scope, receive, send)
                return

        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise PayloadTooLarge(self.max_bytes)
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except PayloadTooLarge:
            if not response_started:
                await self._reject(scope, receive, send)

    async def _reject(self, scope: Scope, receive: Receive, send: Send) -> None:
        response = JSONResponse(
            status_code=400,
            content={
                "error": {
                    "code": "payload_too_large",
                    "message": f"Request body must not exceed {self.max_bytes} bytes.",
                }
            },
        )
        await response(scope, receive, send)


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.setdefault("X-Content-Type-Options", "nosniff")
                headers.setdefault("X-Frame-Options", "DENY")
                headers.setdefault("Referrer-Policy", "no-referrer")
                headers.setdefault("Cache-Control", "no-store")
                headers.setdefault("Pragma", "no-cache")
                headers.setdefault(
                    "Permissions-Policy",
                    "camera=(), microphone=(), geolocation=()",
                )
                path = scope.get("path", "")
                if not path.startswith(("/docs", "/redoc", "/openapi.json")):
                    headers.setdefault(
                        "Content-Security-Policy",
                        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
                    )
                if scope.get("scheme") == "https":
                    headers.setdefault(
                        "Strict-Transport-Security",
                        "max-age=31536000; includeSubDomains",
                    )
            await send(message)

        await self.app(scope, receive, send_with_headers)


class RequestIDMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        incoming = Headers(scope=scope).get("x-request-id")
        request_id = (
            incoming
            if incoming is not None and _REQUEST_ID_RE.fullmatch(incoming)
            else uuid.uuid4().hex
        )
        scope.setdefault("state", {})["request_id"] = request_id

        async def send_with_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message).setdefault("X-Request-ID", request_id)
            await send(message)

        await self.app(scope, receive, send_with_id)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    db.init_db(settings.db_path)

    app = FastAPI(
        title="Nestack Secure Records API",
        version="1.0.0",
        docs_url="/docs" if settings.enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )
    app.state.settings = settings
    app.state.clock = time.time
    app.state.dummy_password_hash = hash_password(
        secrets.token_urlsafe(32),
        n=settings.scrypt_n,
        r=settings.scrypt_r,
        p=settings.scrypt_p,
        pepper=settings.pepper_bytes,
    )

    register_error_handlers(app, logger)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_bytes)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestIDMiddleware)

    app.include_router(auth_router)
    app.include_router(records_router)

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        conn = db.connect(settings.db_path)
        try:
            conn.execute("SELECT 1").fetchone()
        except Exception:
            logger.exception("health_check_failed")
            return JSONResponse(status_code=503, content={"status": "unavailable"})
        finally:
            conn.close()
        return {"status": "ok"}

    logger.info("app_started db_path=%s", settings.db_path)
    return app


def __getattr__(name: str):
    """Allow `uvicorn app.main:app` as well as the documented `app.asgi:app`."""
    if name == "app":
        from app import asgi

        return asgi.app
    raise AttributeError(name)
