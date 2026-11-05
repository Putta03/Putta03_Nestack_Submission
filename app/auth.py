"""Registration, login, lockout, and session checks."""

import logging
import math
import sqlite3
from dataclasses import dataclass

from app import repositories
from app.config import Settings
from app.db import transaction
from app.errors import ApiError
from app.security import (
    hash_password,
    hash_session_token,
    new_session_token,
    verify_password,
)

logger = logging.getLogger("nestack.auth")

INVALID_CREDENTIALS = "Invalid username or password."
LOCKED_MESSAGE = "Too many failed login attempts. Try again later."


@dataclass(frozen=True)
class SessionGrant:
    user_id: int
    token: str
    expires_at: float


def _retry_after(locked_until: float, now: float) -> int:
    return max(1, math.ceil(locked_until - now))


def register(
    conn: sqlite3.Connection,
    settings: Settings,
    username: str,
    password: str,
    now: float,
) -> dict:
    password_hash = hash_password(
        password,
        n=settings.scrypt_n,
        r=settings.scrypt_r,
        p=settings.scrypt_p,
        pepper=settings.pepper_bytes,
    )
    try:
        user_id = repositories.create_user(conn, username, password_hash, now)
    except sqlite3.IntegrityError as exc:
        if "UNIQUE" in str(exc).upper():
            raise ApiError(409, "username_taken", "That username is already registered.") from exc
        raise
    return {"id": user_id, "username": username, "role": "user"}


def login(
    conn: sqlite3.Connection,
    settings: Settings,
    username: str,
    password: str,
    now: float,
    dummy_hash: str,
) -> SessionGrant:
    user = repositories.get_user_by_username(conn, username)

    if user is not None and user["locked_until"] is not None and user["locked_until"] > now:
        retry = _retry_after(user["locked_until"], now)
        raise ApiError(429, "account_locked", LOCKED_MESSAGE, headers={"Retry-After": str(retry)})

    if user is not None:
        # A lock that has expired starts a fresh set of attempts.
        repositories.reset_expired_lock(conn, user["id"], now)

    stored_hash = user["password_hash"] if user is not None else dummy_hash
    valid = verify_password(password, stored_hash, pepper=settings.pepper_bytes)

    if user is None:
        # The dummy hash above makes this path cost the same as a real account.
        logger.info("login_failed user=unknown")
        raise ApiError(401, "invalid_credentials", INVALID_CREDENTIALS)

    if not valid:
        with transaction(conn):
            updated = repositories.record_failed_attempt(
                conn,
                user["id"],
                now,
                settings.lockout_threshold,
                settings.lockout_seconds,
            )
        if updated is not None and updated["locked_until"] is not None and updated["locked_until"] > now:
            retry = _retry_after(updated["locked_until"], now)
            logger.warning("login_locked user_id=%s retry_after=%s", user["id"], retry)
            raise ApiError(429, "account_locked", LOCKED_MESSAGE, headers={"Retry-After": str(retry)})
        logger.info("login_failed user_id=%s", user["id"])
        raise ApiError(401, "invalid_credentials", INVALID_CREDENTIALS)

    token = new_session_token()
    token_hash = hash_session_token(token)
    if token_hash is None:  # pragma: no cover - guards a format change
        raise RuntimeError("session token format changed")
    expires_at = now + settings.session_ttl

    with transaction(conn):
        cleared = conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL "
            "WHERE id = ? AND (locked_until IS NULL OR locked_until <= ?)",
            (user["id"], now),
        )
        if cleared.rowcount == 1:
            repositories.create_session(conn, token_hash, user["id"], now, expires_at)
            repositories.purge_expired_sessions(conn, now)

    if cleared.rowcount != 1:
        # A concurrent request locked the account between the check and here.
        fresh = repositories.get_user_by_id(conn, user["id"])
        if fresh is None:
            raise ApiError(401, "invalid_credentials", INVALID_CREDENTIALS)
        retry = _retry_after(fresh["locked_until"] or now, now)
        raise ApiError(429, "account_locked", LOCKED_MESSAGE, headers={"Retry-After": str(retry)})

    logger.info("login_succeeded user_id=%s", user["id"])
    return SessionGrant(user_id=user["id"], token=token, expires_at=expires_at)


def authenticate(
    conn: sqlite3.Connection,
    token_hash: str,
    now: float,
) -> dict | None:
    row = repositories.get_session_user(conn, token_hash, now)
    if row is None:
        return None
    return {"id": row["id"], "username": row["username"], "role": row["role"]}


def logout(conn: sqlite3.Connection, token_hash: str) -> None:
    repositories.delete_session(conn, token_hash)
