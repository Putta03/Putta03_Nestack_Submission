"""Password hashing and session-token primitives.

No auth framework is used: hashing is stdlib scrypt, tokens are stdlib
`secrets`, and comparison is constant time.
"""

import base64
import binascii
import hashlib
import hmac
import re
import secrets

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_SALT_BYTES = 16
_KEY_BYTES = 32


def _derive(password: str, salt: bytes, n: int, r: int, p: int, pepper: bytes | None) -> bytes:
    material = password.encode("utf-8")
    if pepper:
        # Optional server-side pepper: a DB-only leak is not enough to test guesses.
        material = hmac.new(pepper, material, hashlib.sha256).digest()
    maxmem = 2 * 128 * n * r + 1024 * 1024
    return hashlib.scrypt(material, salt=salt, n=n, r=r, p=p, dklen=_KEY_BYTES, maxmem=maxmem)


def hash_password(
    password: str,
    *,
    n: int,
    r: int,
    p: int,
    pepper: bytes | None = None,
) -> str:
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = _derive(password, salt, n, r, p, pepper)
    return "$".join(
        (
            "scrypt",
            str(n),
            str(r),
            str(p),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(digest).decode("ascii"),
        )
    )


def verify_password(password: str, encoded: str, *, pepper: bytes | None = None) -> bool:
    try:
        algorithm, n_raw, r_raw, p_raw, salt_raw, digest_raw = encoded.split("$")
        if algorithm != "scrypt":
            return False
        n, r, p = int(n_raw), int(r_raw), int(p_raw)
        if n < 2 or n > 2**18 or (n & (n - 1)) != 0:
            return False
        if not (1 <= r <= 32 and 1 <= p <= 16):
            return False
        salt = base64.b64decode(salt_raw, validate=True)
        expected = base64.b64decode(digest_raw, validate=True)
        if len(salt) < _SALT_BYTES or len(expected) != _KEY_BYTES:
            return False
        actual = _derive(password, salt, n, r, p, pepper)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, binascii.Error):
        return False


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def hash_session_token(token: str) -> str | None:
    """Session tokens are stored as SHA-256 hashes, never in plaintext."""
    if not _TOKEN_RE.fullmatch(token):
        return None
    return hashlib.sha256(token.encode("ascii")).hexdigest()
