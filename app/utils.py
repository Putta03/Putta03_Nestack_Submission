"""Small shared helpers."""

from datetime import datetime, timezone

from fastapi import Request


def iso_utc(timestamp: float) -> str:
    return (
        datetime.fromtimestamp(timestamp, tz=timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "-")
