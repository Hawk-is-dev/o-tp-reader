"""
Session reading helpers.

Supports:
  - Telethon session STRING (pasted as text)
  - Telethon .session FILE (SQLite) — read via raw SQL instead of Telethon's
    own SQLiteSession loader, which can crash with "too many values to
    unpack" when the file was saved by a different Telethon schema version
    than the one installed here. Reading dc_id/server_address/port/auth_key
    directly and building a fresh StringSession avoids that entirely.
  - .zip containing one or more .session files

Pyrogram strings/files and tdata folders are intentionally NOT handled here
(out of scope for this bot) — a zip entry in an unsupported format is simply
reported as invalid/skipped rather than crashing the batch.
"""

import os
import sqlite3
import zipfile

from telethon.sessions import StringSession
from telethon.crypto import AuthKey


def _sqlite_session_kind(path: str) -> str:
    """Peeks at the sqlite table names to tell a Telethon session file apart
    from anything else, without trying to fully load it."""
    try:
        conn = sqlite3.connect(path)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cur.fetchall()}
        conn.close()
    except Exception:
        return "unknown"
    if {"sessions", "entities"} <= tables:
        return "telethon"
    if {"sessions", "peers"} <= tables:
        return "pyrogram"
    return "unknown"


def _read_telethon_sqlite_raw(path: str):
    """Reads dc_id/server_address/port/auth_key directly via raw SQL,
    bypassing Telethon's own fragile SQLiteSession schema-upgrade path."""
    conn = sqlite3.connect(path)
    try:
        row = conn.execute(
            "SELECT dc_id, server_address, port, auth_key FROM sessions LIMIT 1"
        ).fetchone()
    finally:
        conn.close()

    if not row:
        raise ValueError("No session row found inside the .session file.")

    dc_id, server_address, port, auth_key_bytes = row
    if not auth_key_bytes:
        raise ValueError("This .session file has no auth key saved — it was never logged in.")

    return dc_id, server_address, port, auth_key_bytes


def session_string_from_telethon_file(path: str) -> str:
    """Builds a plain Telethon StringSession string from a .session file,
    without ever touching Telethon's SQLiteSession loader."""
    dc_id, server_address, port, auth_key_bytes = _read_telethon_sqlite_raw(path)
    session = StringSession()
    session.set_dc(dc_id, server_address, port)
    session.auth_key = AuthKey(data=auth_key_bytes)
    return session.save()


def extract_zip_sessions(zip_path: str, work_dir: str):
    """Extracts a .zip and returns a list of dicts, one per .session file found:
        {"name": filename, "session": str | None, "error": str | None}
    Never raises for an individual bad file — bad entries just carry an error
    so the caller can report "X of N valid" and keep going."""
    extract_dir = os.path.join(work_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(extract_dir)

    session_files = []
    for root, _dirs, files in os.walk(extract_dir):
        for f in files:
            if f.lower().endswith(".session"):
                session_files.append(os.path.join(root, f))

    results = []
    for sf in session_files:
        name = os.path.basename(sf)
        kind = _sqlite_session_kind(sf)
        if kind == "telethon":
            try:
                sess_str = session_string_from_telethon_file(sf)
                results.append({"name": name, "session": sess_str, "error": None})
            except Exception as e:
                results.append({"name": name, "session": None, "error": str(e)})
        elif kind == "pyrogram":
            results.append({"name": name, "session": None, "error": "Pyrogram .session files aren't supported in this bot."})
        else:
            results.append({"name": name, "session": None, "error": "Unrecognized .session file format."})

    return results
