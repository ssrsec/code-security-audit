from __future__ import annotations

import sqlite3


def user_report_handler(request):
    """HTTP-style handler used by production tools generic smoke tests."""
    user_id = request.query["user_id"]
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT email, balance FROM users WHERE id = '%s'" % user_id
    return cursor.execute(query).fetchall()


def healthcheck_handler(_request):
    return {"ok": True}
