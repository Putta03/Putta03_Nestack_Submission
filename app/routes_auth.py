"""Account and session routes."""

import logging
import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response

from app import auth
from app.deps import AuthContext, get_auth_context, get_db
from app.errors import ApiError
from app.schemas import LoginOut, LoginRequest, RegisterRequest, UserOut
from app.utils import iso_utc, request_id

router = APIRouter()
logger = logging.getLogger("nestack.routes.auth")


@router.post("/register", status_code=201, response_model=UserOut)
def register(
    payload: RegisterRequest,
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_db)],
) -> dict:
    if "role" in payload.model_fields_set:
        raise ApiError(
            403,
            "role_assignment_forbidden",
            "Role is assigned by the server and cannot be set by clients.",
        )

    user = auth.register(
        conn,
        request.app.state.settings,
        payload.username,
        payload.password,
        request.app.state.clock(),
    )
    logger.info("user_registered user_id=%s request_id=%s", user["id"], request_id(request))
    return user


@router.post("/login", response_model=LoginOut)
def login(
    payload: LoginRequest,
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_db)],
) -> dict:
    grant = auth.login(
        conn,
        request.app.state.settings,
        payload.username,
        payload.password,
        request.app.state.clock(),
        request.app.state.dummy_password_hash,
    )
    logger.info("login_ok user_id=%s request_id=%s", grant.user_id, request_id(request))
    return {
        "token": grant.token,
        "token_type": "Bearer",
        "expires_at": iso_utc(grant.expires_at),
        "expires_in": request.app.state.settings.session_ttl,
    }


@router.post("/logout", status_code=204)
def logout(
    request: Request,
    ctx: Annotated[AuthContext, Depends(get_auth_context)],
    conn: Annotated[sqlite3.Connection, Depends(get_db)],
) -> Response:
    auth.logout(conn, ctx.token_hash)
    logger.info("logout user_id=%s request_id=%s", ctx.user["id"], request_id(request))
    return Response(status_code=204)
