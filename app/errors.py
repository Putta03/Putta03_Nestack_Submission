"""Uniform JSON error responses."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


class ApiError(Exception):
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        *,
        details: list[dict[str, str]] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details or []
        self.headers = headers


def _json(
    status_code: int,
    code: str,
    message: str,
    *,
    details: list[dict[str, str]] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    payload = {"error": {"code": code, "message": message}}
    if details:
        payload["error"]["details"] = details
    return JSONResponse(status_code=status_code, content=payload, headers=headers)


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "-")


def register_error_handlers(app: FastAPI, logger: logging.Logger) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(_request: Request, exc: ApiError) -> JSONResponse:
        return _json(
            exc.status_code,
            exc.code,
            exc.message,
            details=exc.details,
            headers=exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
        details = []
        for error in exc.errors():
            if error.get("type") == "json_invalid":
                details.append({"field": "body", "message": "Body must be valid JSON."})
                continue
            location = [
                str(part)
                for part in error.get("loc", ())
                if part not in {"body", "query", "path", "header"}
            ]
            details.append(
                {
                    "field": ".".join(location) or "request",
                    "message": error.get("msg", "Invalid value."),
                }
            )
        return _json(400, "invalid_input", "Request validation failed.", details=details)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        custom_code = getattr(exc, "code", None)
        if custom_code:
            message = exc.detail if isinstance(exc.detail, str) else "Request failed."
            return _json(exc.status_code, custom_code, message, headers=exc.headers)
        if exc.status_code == 404:
            message = "Resource not found."
            code = "not_found"
        elif exc.status_code == 405:
            message = "Method not allowed."
            code = "method_not_allowed"
        elif exc.status_code == 401:
            message = "Authentication required."
            code = "unauthorized"
        else:
            message = exc.detail if isinstance(exc.detail, str) else "Request failed."
            code = "http_error"
        return _json(exc.status_code, code, message, headers=exc.headers)

    @app.exception_handler(Exception)
    async def _unhandled_error(request: Request, exc: Exception) -> JSONResponse:
        # Log the details server-side; never return a stack trace or internals.
        logger.exception("unhandled error request_id=%s", _request_id(request))
        return _json(500, "internal_error", "An internal error occurred.")
