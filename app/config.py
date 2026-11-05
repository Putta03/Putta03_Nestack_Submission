"""Environment-driven configuration."""

import os
from dataclasses import dataclass


def _int(name: str, default: int, *, minimum: int | None = None) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if minimum is not None and value < minimum:
        raise RuntimeError(f"{name} must be at least {minimum}")
    return value


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    db_path: str = "nestack.db"
    session_ttl: int = 8 * 60 * 60
    lockout_threshold: int = 5
    lockout_seconds: int = 15 * 60
    max_body_bytes: int = 64 * 1024
    scrypt_n: int = 2**15
    scrypt_r: int = 8
    scrypt_p: int = 1
    pepper: str | None = None
    enable_docs: bool = True
    log_level: str = "INFO"

    def __post_init__(self) -> None:
        if self.scrypt_n < 2 or (self.scrypt_n & (self.scrypt_n - 1)) != 0:
            raise ValueError("scrypt_n must be a power of two >= 2")
        if self.scrypt_n > 2**18:
            raise ValueError("scrypt_n must be <= 2^18")
        if not (1 <= self.scrypt_r <= 32) or not (1 <= self.scrypt_p <= 16):
            raise ValueError("scrypt_r must be 1-32 and scrypt_p must be 1-16")
        if self.pepper is not None and len(self.pepper) < 16:
            raise ValueError("the password pepper must be at least 16 characters")

    @property
    def pepper_bytes(self) -> bytes | None:
        return self.pepper.encode("utf-8") if self.pepper else None

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            db_path=os.getenv("NESTACK_DB_PATH", "nestack.db"),
            session_ttl=_int("NESTACK_SESSION_TTL", 8 * 60 * 60, minimum=60),
            lockout_threshold=_int("NESTACK_LOCKOUT_THRESHOLD", 5, minimum=1),
            lockout_seconds=_int("NESTACK_LOCKOUT_SECONDS", 15 * 60, minimum=1),
            max_body_bytes=_int("NESTACK_MAX_BODY_BYTES", 64 * 1024, minimum=1024),
            scrypt_n=_int("NESTACK_SCRYPT_N", 2**15, minimum=2),
            scrypt_r=_int("NESTACK_SCRYPT_R", 8, minimum=1),
            scrypt_p=_int("NESTACK_SCRYPT_P", 1, minimum=1),
            pepper=os.getenv("NESTACK_PASSWORD_PEPPER") or None,
            enable_docs=_bool("NESTACK_ENABLE_DOCS", True),
            log_level=os.getenv("NESTACK_LOG_LEVEL", "INFO").upper(),
        )
