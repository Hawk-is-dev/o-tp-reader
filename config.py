import os

# Fill these in on your server / Render / Railway env vars. Never commit real values.
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
API_ID = int(os.getenv("API_ID", "0"))      # from my.telegram.org
API_HASH = os.getenv("API_HASH", "")        # from my.telegram.org

# One or more Telegram numeric user IDs allowed to use this bot, comma-separated.
# Each owner's data (pending resets, Watchman list, saved-session backups) is
# kept completely separate — one owner can never see another's accounts.
# Back-compat: old single OWNER_ID still works if OWNER_IDS isn't set.
_owner_ids_raw = os.getenv("OWNER_IDS", "") or os.getenv("OWNER_ID", "")
OWNER_IDS = {int(x.strip()) for x in _owner_ids_raw.split(",") if x.strip()}

# Watchman: a new login whose device model matches this (case-insensitive)
# is treated as you, not an intruder, and is never auto-terminated.
TRUSTED_DEVICE_MODEL = os.getenv("TRUSTED_DEVICE_MODEL", "Lenovo Lenovo Tab M8")

# MongoDB connection string (free tier on MongoDB Atlas works fine) — used to
# persist pending resets, Watchman list, and session backups across restarts.
# Safe to reuse the same MONGO_URI as another bot/project — this bot keeps
# all its data inside its own database (MONGO_DB_NAME below), so nothing
# collides with whatever that other bot stores.
MONGO_URI = os.getenv("MONGO_URI", "")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "otp_reader")

# Used to encrypt every session string before it's stored in MongoDB. Set
# this to any long random string and never change it once sessions are
# stored, or they become undecryptable. Generate one with:
#   python -c "import secrets; print(secrets.token_urlsafe(32))"
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "")

# ---------------------------------------------------------------------------
# Bulk Email Change — generates a unique name+label@domain address per
# account (Gmail-style "plus addressing": everything after "+" is ignored
# for delivery, so all the codes land in one inbox) and reads the
# verification code for you via IMAP, so a whole .zip can be processed
# hands-off, one account at a time.
# ---------------------------------------------------------------------------

# Your real inbox, e.g. harsh123@gmail.com — every generated address is
# <local>+<label>@<domain> built from this.
BASE_EMAIL = os.getenv("BASE_EMAIL", "")

# IMAP login for that same inbox (usually identical to BASE_EMAIL) and an
# App Password (myaccount.google.com/apppasswords — requires 2-Step
# Verification to be on). Never your normal account password.
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS", "")
EMAIL_APP_PASSWORD = os.getenv("EMAIL_APP_PASSWORD", "")
EMAIL_IMAP_HOST = os.getenv("EMAIL_IMAP_HOST", "imap.gmail.com")
EMAIL_IMAP_PORT = int(os.getenv("EMAIL_IMAP_PORT", "993"))

# How long to wait for Telegram's code to arrive by email before giving up
# on one account (seconds), and how long to pause between accounts in a
# bulk run so Telegram doesn't see a burst of email-change requests.
EMAIL_WAIT_SECONDS = int(os.getenv("EMAIL_WAIT_SECONDS", "90"))
EMAIL_BULK_DELAY_SECONDS = int(os.getenv("EMAIL_BULK_DELAY_SECONDS", "8"))
