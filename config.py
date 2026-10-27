import os

# Fill these in on your server / Railway env vars. Never commit real values.
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
OWNER_ID = int(os.getenv("OWNER_ID", "0"))  # your own Telegram numeric user ID
API_ID = int(os.getenv("API_ID", "0"))      # from my.telegram.org
API_HASH = os.getenv("API_HASH", "")        # from my.telegram.org
