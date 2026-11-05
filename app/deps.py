"""FastAPI dependencies for the database and the authenticated session."""

import sqlite3
from dataclasses import dataclass
from typing import Annotated, Iterator

from fastapi import Depends, Header, Request

from app import auth, db, security
from app.errors import ApiError

_UNAUTHORIZED_HEADERS = {"WWW-Authenticate": "Bearer"}


@dataclass(frozen=True)
class AuthContext:
    user: dict
    token: str
    token_hash: str


def get_db(request: Request) -> Iterator[sqlite3.Connection]:
    conn = db.connect(request.app.state.settings.db_path)
    try:
        yield conn
    finally:
        conn.close()


def get_auth_context(
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
) -> AuthContext:
    if not authorization:
        raise ApiError(401, "unauthorized", "Authentication required.", headers=_UNAUTHORIZED_HEADERS)

    scheme, _, token = authorization.partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        raise ApiError(401, "unauthorized", "Authentication required.", headers=_UNAUTHORIZED_HEADERS)

    token_hash = security.hash_session_token(token)
    if token_hash is None:
        raise ApiError(401, "unauthorized", "Authentication required.", headers=_UNAUTHORIZED_HEADERS)

    user = auth.authenticate(conn, token_hash, request.app.state.clock())
    if user is None:
        raise ApiError(401, "unauthorized", "Authentication required.", headers=_UNAUTHORIZED_HEADERS)

    return AuthContext(user=user, token=token, token_hash=token_hash)


def get_current_user(ctx: Annotated[AuthContext, Depends(get_auth_context)]) -> dict:
    return ctx.user
