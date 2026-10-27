"""
Session reading helpers.

Supports:
  - Telethon session STRING (pasted as text)
  - Pyrogram session STRING (pasted as text) — auto-detected and converted
  - Telethon .session FILE (SQLite) — read via raw SQL instead of Telethon's
    own SQLiteSession loader, which can crash with "too many values to
    unpack" when the file was saved by a different Telethon schema version
    than the one installed here. Reading dc_id/server_address/port/auth_key
    directly and building a fresh StringSession avoids that entirely.
  - Pyrogram .session FILE — converted to a Telethon session via
    `telegram-session-converter`
  - .zip containing a mix of Telethon/Pyrogram .session files

Needs: pip install telegram-session-converter --break-system-packages
(Telethon-only string/.session input still works without it; Pyrogram
input will raise a clear "not installed" error instead of crashing.)

tdata folders are intentionally not handled here (out of scope for this bot).
"""

import os
import sqlite3
import uuid
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


def _get_session_manager():
    try:
        from session_converter import SessionManager
    except ImportError:
        raise RuntimeError(
            "Pyrogram session support is not installed on this server "
            "(pip install telegram-session-converter --break-system-packages)."
        )
    return SessionManager


def session_string_from_pyrogram_string(pyrogram_string: str, work_dir: str) -> str:
    """Converts a Pyrogram session string into a Telethon session string."""
    SessionManager = _get_session_manager()
    sm = SessionManager.from_pyrogram_string_session(pyrogram_string)
    out_path = os.path.join(work_dir, f"converted_{uuid.uuid4().hex}.session")
    sm.telethon_file(out_path)
    return session_string_from_telethon_file(out_path)


def session_string_from_pyrogram_file(path: str, work_dir: str) -> str:
    """Converts a Pyrogram .session file into a Telethon session string."""
    SessionManager = _get_session_manager()
    sm = SessionManager.from_pyrogram_session_file(path)
    out_path = os.path.join(work_dir, f"converted_{uuid.uuid4().hex}.session")
    sm.telethon_file(out_path)
    return session_string_from_telethon_file(out_path)


def session_string_from_file(path: str, work_dir: str) -> str:
    """Auto-detects a .session file's format (Telethon or Pyrogram) and
    returns a Telethon session string either way."""
    kind = _sqlite_session_kind(path)
    if kind == "telethon":
        return session_string_from_telethon_file(path)
    if kind == "pyrogram":
        return session_string_from_pyrogram_file(path, work_dir)
    raise ValueError("Unrecognized .session file format.")


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
        try:
            sess_str = session_string_from_file(sf, work_dir)
            results.append({"name": name, "session": sess_str, "error": None})
        except Exception as e:
            results.append({"name": name, "session": None, "error": str(e)})

    return results
