from pathlib import Path

PASSWORD = "correct horse battery staple"


def db_bytes(db_path: str) -> bytes:
    """Return the main DB plus WAL, so plaintext-leak checks cover both."""
    path = Path(db_path)
    data = path.read_bytes() if path.exists() else b""
    for suffix in ("-wal", "-shm"):
        extra = Path(str(path) + suffix)
        if extra.exists():
            data += extra.read_bytes()
    return data
