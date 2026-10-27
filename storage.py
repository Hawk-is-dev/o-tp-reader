"""
Tiny JSON-file store for pending 2-Step password-reset requests.

Kept deliberately simple (no DB) since this bot is single-owner and low
volume — but it still needs to survive a bot restart, because the 7-day
Telegram wait period is much longer than any single process lifetime.
"""

import json
import os
import threading

STORE_PATH = os.getenv("RESET_STORE_PATH", "pending_resets.json")
_lock = threading.Lock()


def _load() -> dict:
    if not os.path.exists(STORE_PATH):
        return {}
    try:
        with open(STORE_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def _save(data: dict) -> None:
    tmp_path = STORE_PATH + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, STORE_PATH)


def add_pending(entry_id: str, phone: str, session: str, until_date_iso: str) -> None:
    with _lock:
        data = _load()
        data[entry_id] = {
            "phone": phone,
            "session": session,
            "until_date": until_date_iso,
            "notified_ready": False,
        }
        _save(data)


def update_until_date(entry_id: str, until_date_iso: str) -> None:
    with _lock:
        data = _load()
        if entry_id in data:
            data[entry_id]["until_date"] = until_date_iso
            data[entry_id]["notified_ready"] = False
            _save(data)


def mark_notified(entry_id: str) -> None:
    with _lock:
        data = _load()
        if entry_id in data:
            data[entry_id]["notified_ready"] = True
            _save(data)


def remove_pending(entry_id: str) -> None:
    with _lock:
        data = _load()
        data.pop(entry_id, None)
        _save(data)


def get_all_pending() -> dict:
    with _lock:
        return _load()


def get_pending(entry_id: str):
    with _lock:
        return _load().get(entry_id)
