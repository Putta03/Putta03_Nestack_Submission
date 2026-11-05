"""All SQL lives here and every query is parameterised."""

import sqlite3

VALID_ROLES = ("user", "admin")


def create_user(conn: sqlite3.Connection, username: str, password_hash: str, now: float) -> int:
    # The role is a string literal, never a value supplied by the request.
    cursor = conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at) "
        "VALUES (?, ?, 'user', ?)",
        (username, password_hash, now),
    )
    return int(cursor.lastrowid)


def get_user_by_username(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, username, role, password_hash, failed_attempts, locked_until, created_at "
        "FROM users WHERE username = ?",
        (username,),
    ).fetchone()


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, username, role, password_hash, failed_attempts, locked_until, created_at "
        "FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()


def set_role(conn: sqlite3.Connection, user_id: int, role: str) -> None:
    if role not in VALID_ROLES:
        raise ValueError(f"invalid role: {role}")
    conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))


def record_failed_attempt(
    conn: sqlite3.Connection,
    user_id: int,
    now: float,
    threshold: int,
    lockout_seconds: int,
) -> sqlite3.Row | None:
    # One statement, so concurrent failures cannot lose an increment.
    return conn.execute(
        """
        UPDATE users
           SET failed_attempts = failed_attempts + 1,
               locked_until = CASE
                   WHEN failed_attempts + 1 >= ? THEN ?
                   ELSE NULL
               END
         WHERE id = ?
     RETURNING failed_attempts, locked_until
        """,
        (threshold, now + lockout_seconds, user_id),
    ).fetchone()


def reset_expired_lock(conn: sqlite3.Connection, user_id: int, now: float) -> None:
    conn.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL "
        "WHERE id = ? AND locked_until IS NOT NULL AND locked_until <= ?",
        (user_id, now),
    )


def create_record(
    conn: sqlite3.Connection,
    owner_id: int,
    title: str,
    body: str,
    now: float,
) -> int:
    cursor = conn.execute(
        "INSERT INTO records (owner_id, title, body, created_at) VALUES (?, ?, ?, ?)",
        (owner_id, title, body, now),
    )
    return int(cursor.lastrowid)


def get_record(conn: sqlite3.Connection, record_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, owner_id, title, body, created_at FROM records WHERE id = ?",
        (record_id,),
    ).fetchone()


def create_session(
    conn: sqlite3.Connection,
    token_hash: str,
    user_id: int,
    now: float,
    expires_at: float,
) -> None:
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) "
        "VALUES (?, ?, ?, ?)",
        (token_hash, user_id, now, expires_at),
    )


def get_session_user(conn: sqlite3.Connection, token_hash: str, now: float) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT u.id, u.username, u.role
          FROM sessions s
          JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ? AND s.expires_at > ?
        """,
        (token_hash, now),
    ).fetchone()


def delete_session(conn: sqlite3.Connection, token_hash: str) -> None:
    conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))


def purge_expired_sessions(conn: sqlite3.Connection, now: float) -> None:
    conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
