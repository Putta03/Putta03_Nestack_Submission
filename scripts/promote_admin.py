#!/usr/bin/env python3
"""Grant or revoke the admin role directly in the database.

This is the only way to create an admin: no HTTP endpoint can change a role.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import db, repositories
from app.config import Settings


def main() -> int:
    parser = argparse.ArgumentParser(description="Set a user's role server-side.")
    parser.add_argument("username")
    parser.add_argument("--role", choices=("user", "admin"), default="admin")
    args = parser.parse_args()

    settings = Settings.from_env()
    db.init_db(settings.db_path)
    conn = db.connect(settings.db_path)
    try:
        user = repositories.get_user_by_username(conn, args.username)
        if user is None:
            print(f"No such user: {args.username}", file=sys.stderr)
            return 1
        repositories.set_role(conn, user["id"], args.role)
        print(f"{user['username']} is now {args.role}")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
