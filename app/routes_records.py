"""Record routes. Ownership is checked on every read."""

import logging
import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, Request

from app import repositories
from app.deps import get_current_user, get_db
from app.errors import ApiError
from app.schemas import RecordCreate, RecordOut
from app.utils import iso_utc, request_id

router = APIRouter()
logger = logging.getLogger("nestack.routes.records")


def _serialise(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "title": row["title"],
        "body": row["body"],
        "created_at": iso_utc(row["created_at"]),
    }


@router.post("/records", status_code=201, response_model=RecordOut)
def create_record(
    payload: RecordCreate,
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_db)],
    user: Annotated[dict, Depends(get_current_user)],
) -> dict:
    now = request.app.state.clock()
    # The owner always comes from the session, never from the request body.
    record_id = repositories.create_record(conn, user["id"], payload.title, payload.body, now)
    row = repositories.get_record(conn, record_id)
    if row is None:  # pragma: no cover - insert just succeeded
        raise RuntimeError("record disappeared after insert")
    logger.info(
        "record_created user_id=%s record_id=%s request_id=%s",
        user["id"],
        record_id,
        request_id(request),
    )
    return _serialise(row)


@router.get("/records/{record_id}", response_model=RecordOut)
def read_record(
    record_id: int,
    request: Request,
    conn: Annotated[sqlite3.Connection, Depends(get_db)],
    user: Annotated[dict, Depends(get_current_user)],
) -> dict:
    row = repositories.get_record(conn, record_id)
    if row is None or (row["owner_id"] != user["id"] and user["role"] != "admin"):
        # Same response for missing and not-owned: do not confirm that an id exists.
        raise ApiError(404, "record_not_found", "Record not found.")

    if user["role"] == "admin" and row["owner_id"] != user["id"]:
        logger.info(
            "admin_record_read admin_id=%s record_id=%s owner_id=%s request_id=%s",
            user["id"],
            record_id,
            row["owner_id"],
            request_id(request),
        )
    return _serialise(row)
