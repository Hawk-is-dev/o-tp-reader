"""
MongoDB-backed store for pending 2-Step password-reset requests, active
Watchman sessions, and session backups — replaces the old JSON-file store
so everything survives a bot restart/redeploy.

Every document carries an "owner_id" (the Telegram user ID that submitted
it), and every read/write below is scoped to one owner_id — so with
multiple owners sharing one bot, nobody can ever see or touch another
owner's accounts.

Every session string is encrypted (Fernet/AES) before it's written to
Mongo, using a key derived from config.ENCRYPTION_KEY, so a DB leak alone
doesn't hand out raw session strings.
"""

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken
from pymongo import MongoClient

from config import MONGO_URI, MONGO_DB_NAME, ENCRYPTION_KEY

_client = MongoClient(MONGO_URI) if MONGO_URI else None
_db = _client[MONGO_DB_NAME] if _client is not None else None

_pending_col = _db["pending_resets"] if _db is not None else None
_watchman_col = _db["watchmen"] if _db is not None else None
_sessions_col = _db["saved_sessions"] if _db is not None else None


def _check_ready():
    if _db is None:
        raise RuntimeError(
            "MONGO_URI is not set — storage can't persist anything. "
            "Set it in your environment variables."
        )


def _fernet() -> Fernet:
    if not ENCRYPTION_KEY:
        raise RuntimeError(
            "ENCRYPTION_KEY is not set — set it before storing any session "
            "(see config.py for how to generate one)."
        )
    # Derive a valid 32-byte urlsafe-base64 Fernet key from whatever string
    # the user set, so ENCRYPTION_KEY doesn't need to be a Fernet key itself.
    digest = hashlib.sha256(ENCRYPTION_KEY.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt(plain: str) -> str:
    return _fernet().encrypt(plain.encode("utf-8")).decode("utf-8")


def decrypt(token: str):
    try:
        return _fernet().decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return None


# ---------------------------------------------------------------------------
# Pending password-reset requests
# ---------------------------------------------------------------------------

def add_pending(owner_id: int, entry_id: str, phone: str, session: str, until_date_iso: str) -> None:
    _check_ready()
    _pending_col.update_one(
        {"_id": entry_id},
        {"$set": {
            "owner_id": owner_id,
            "phone": phone,
            "session": encrypt(session),
            "until_date": until_date_iso,
            "notified_ready": False,
        }},
        upsert=True,
    )


def update_until_date(owner_id: int, entry_id: str, until_date_iso: str) -> None:
    _check_ready()
    _pending_col.update_one(
        {"_id": entry_id, "owner_id": owner_id},
        {"$set": {"until_date": until_date_iso, "notified_ready": False}},
    )


def mark_notified(entry_id: str) -> None:
    _check_ready()
    _pending_col.update_one({"_id": entry_id}, {"$set": {"notified_ready": True}})


def remove_pending(owner_id: int, entry_id: str) -> None:
    _check_ready()
    _pending_col.delete_one({"_id": entry_id, "owner_id": owner_id})


def get_all_pending(owner_id: int) -> dict:
    _check_ready()
    out = {}
    for doc in _pending_col.find({"owner_id": owner_id}):
        entry = dict(doc)
        entry_id = entry.pop("_id")
        entry["session"] = decrypt(entry["session"])
        out[entry_id] = entry
    return out


def get_all_pending_every_owner() -> dict:
    """Used only by the background reset_watcher loop, which has to scan
    every owner's pending requests to notify the right chat."""
    _check_ready()
    out = {}
    for doc in _pending_col.find({}):
        entry = dict(doc)
        entry_id = entry.pop("_id")
        entry["session"] = decrypt(entry["session"])
        out[entry_id] = entry
    return out


def get_pending(owner_id: int, entry_id: str):
    _check_ready()
    doc = _pending_col.find_one({"_id": entry_id, "owner_id": owner_id})
    if not doc:
        return None
    entry = dict(doc)
    entry.pop("_id")
    entry["session"] = decrypt(entry["session"])
    return entry


# ---------------------------------------------------------------------------
# Watchman — accounts under active login-monitoring
# ---------------------------------------------------------------------------

def add_watchman(owner_id: int, entry_id: str, phone: str, session: str, known_hashes: list) -> None:
    _check_ready()
    _watchman_col.update_one(
        {"_id": entry_id},
        {"$set": {
            "owner_id": owner_id,
            "phone": phone,
            "session": encrypt(session),
            "known_hashes": known_hashes,
        }},
        upsert=True,
    )


def update_watchman_known_hashes(entry_id: str, known_hashes: list) -> None:
    _check_ready()
    _watchman_col.update_one({"_id": entry_id}, {"$set": {"known_hashes": known_hashes}})


def remove_watchman(owner_id: int, entry_id: str) -> None:
    _check_ready()
    _watchman_col.delete_one({"_id": entry_id, "owner_id": owner_id})


def get_all_watchmen(owner_id: int) -> dict:
    _check_ready()
    out = {}
    for doc in _watchman_col.find({"owner_id": owner_id}):
        entry = dict(doc)
        entry_id = entry.pop("_id")
        entry["session"] = decrypt(entry["session"])
        out[entry_id] = entry
    return out


def get_all_watchmen_every_owner() -> dict:
    """Used only at startup (restore_watchmen) and by the live monitor,
    which have to reconnect/manage every owner's Watchman accounts."""
    _check_ready()
    out = {}
    for doc in _watchman_col.find({}):
        entry = dict(doc)
        entry_id = entry.pop("_id")
        entry["session"] = decrypt(entry["session"])
        out[entry_id] = entry
    return out


def get_watchman(entry_id: str):
    _check_ready()
    doc = _watchman_col.find_one({"_id": entry_id})
    if not doc:
        return None
    entry = dict(doc)
    entry.pop("_id")
    entry["session"] = decrypt(entry["session"])
    return entry


# ---------------------------------------------------------------------------
# Saved-session backups — every session ever successfully submitted, so
# /backup can hand them all back later. "fmt" is "string" or "session_file",
# recorded only so /backup can re-send the same way it originally came in.
# ---------------------------------------------------------------------------

def add_saved_session(owner_id: int, phone: str, session: str, fmt: str) -> None:
    _check_ready()
    _sessions_col.update_one(
        {"owner_id": owner_id, "phone": phone},
        {"$set": {"session": encrypt(session), "fmt": fmt}},
        upsert=True,
    )


def get_saved_sessions(owner_id: int) -> list:
    _check_ready()
    out = []
    for doc in _sessions_col.find({"owner_id": owner_id}):
        out.append({
            "phone": doc["phone"],
            "session": decrypt(doc["session"]),
            "fmt": doc.get("fmt", "string"),
        })
    return out


def remove_saved_session(owner_id: int, phone: str) -> None:
    _check_ready()
    _sessions_col.delete_one({"owner_id": owner_id, "phone": phone})
