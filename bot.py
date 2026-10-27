import asyncio
import logging
import os
import re
import tempfile
import uuid

from aiogram import Bot, Dispatcher, F, types
from aiogram.filters import Command
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup
from aiogram.fsm.storage.memory import MemoryStorage

from telethon import TelegramClient
from telethon.sessions import StringSession

from config import BOT_TOKEN, OWNER_ID, API_ID, API_HASH
from session_utils import session_string_from_telethon_file, extract_zip_sessions

logging.basicConfig(level=logging.INFO)

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher(storage=MemoryStorage())

# In-memory account registry: account_id -> {"session": str, "phone": str}
# Nothing here is ever logged out / destroyed — this bot only ever reads.
ACCOUNTS = {}

# In-memory batch state for the current .zip run (single-owner bot, so one
# global dict is enough — no multi-user concurrency to worry about).
BATCH = {
    "items": [],     # list of {"name","session","phone","status","error","account_id"}
    "index": -1,
    "success": 0,
    "failed": 0,
    "active": False,
}

# Telegram's official "Login code" messages come from this service user id.
TELEGRAM_SERVICE_ID = 777000
OTP_CODE_RE = re.compile(r"\b(\d{4,7})\b")


def is_owner(user_id: int) -> bool:
    return OWNER_ID != 0 and user_id == OWNER_ID


def gen_account_id() -> str:
    return uuid.uuid4().hex[:10]


def account_kb(account_id: str, with_next: bool = False) -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(text="🔑 Check OTP", callback_data=f"checkotp_{account_id}")]]
    if with_next:
        rows.append([InlineKeyboardButton(text="➡️ Next", callback_data="batch_next")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


async def login_and_get_phone(session_string: str):
    """Connects on demand, fetches the phone number, disconnects.
    Never calls log_out() — a failed/expired session is just reported,
    never destroyed. Returns (phone, error)."""
    client = TelegramClient(StringSession(session_string), API_ID, API_HASH)
    try:
        await client.connect()
        if not await client.is_user_authorized():
            return None, "Session is not authorized (logged out or invalid)."
        me = await client.get_me()
        phone = f"+{me.phone}" if me.phone else "Unknown"
        return phone, None
    except Exception as e:
        return None, str(e)
    finally:
        await client.disconnect()


# ---------------------------------------------------------------------------
# /start
# ---------------------------------------------------------------------------

@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    if not is_owner(message.from_user.id):
        return
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📤 Send Session", callback_data="send_session")]
    ])
    await message.answer(
        "👋 Welcome!\n\n"
        "Tap the button below, then send a session as:\n"
        "• a session string\n"
        "• a .session file\n"
        "• a .zip containing multiple .session files",
        reply_markup=kb
    )


@dp.callback_query(F.data == "send_session")
async def prompt_send_session(callback: types.CallbackQuery):
    if not is_owner(callback.from_user.id):
        return
    await callback.message.edit_text("📤 Send the session now — as text, a .session file, or a .zip.")
    await callback.answer()


# ---------------------------------------------------------------------------
# Single session string
# ---------------------------------------------------------------------------

@dp.message(F.text & ~F.text.startswith("/"))
async def handle_session_text(message: types.Message):
    if not is_owner(message.from_user.id):
        return
    session_string = message.text.strip()
    if len(session_string) < 20:
        return  # clearly not a session string, ignore quietly

    status = await message.answer("🔍 Logging in, please wait...")
    phone, error = await login_and_get_phone(session_string)
    if error:
        await status.edit_text(f"❌ Could not log in with this session.\n\nReason: {error}")
        return

    account_id = gen_account_id()
    ACCOUNTS[account_id] = {"session": session_string, "phone": phone}
    await status.edit_text(
        f"✅ Logged in!\n\n📱 Number: `{phone}`",
        parse_mode="Markdown",
        reply_markup=account_kb(account_id)
    )


# ---------------------------------------------------------------------------
# .session file / .zip
# ---------------------------------------------------------------------------

@dp.message(F.document)
async def handle_session_document(message: types.Message):
    if not is_owner(message.from_user.id):
        return

    doc = message.document
    file_name = doc.file_name or "upload"
    work_dir = tempfile.mkdtemp(prefix="otp_session_")
    local_path = os.path.join(work_dir, file_name)

    tg_file = await bot.get_file(doc.file_id)
    await bot.download_file(tg_file.file_path, local_path)

    if file_name.lower().endswith(".zip"):
        await handle_zip_upload(message, local_path, work_dir)
        return

    if file_name.lower().endswith(".session"):
        status = await message.answer("🔍 Reading session file, please wait...")
        try:
            session_string = session_string_from_telethon_file(local_path)
        except Exception as e:
            await status.edit_text(f"❌ Session invalid.\n\nReason: {e}")
            return

        phone, error = await login_and_get_phone(session_string)
        if error:
            await status.edit_text(f"❌ Could not log in with this session.\n\nReason: {error}")
            return

        account_id = gen_account_id()
        ACCOUNTS[account_id] = {"session": session_string, "phone": phone}
        await status.edit_text(
            f"✅ Logged in!\n\n📱 Number: `{phone}`",
            parse_mode="Markdown",
            reply_markup=account_kb(account_id)
        )
        return

    await message.answer("❌ Unsupported file type. Send a session string, a .session file, or a .zip.")


async def handle_zip_upload(message: types.Message, zip_path: str, work_dir: str):
    status = await message.answer("🔍 Reading .zip, please wait...")
    raw_items = extract_zip_sessions(zip_path, work_dir)
    total = len(raw_items)

    items = []
    for item in raw_items:
        if item["error"]:
            items.append({**item, "phone": None, "status": "invalid"})
            continue
        phone, login_error = await login_and_get_phone(item["session"])
        if login_error:
            items.append({**item, "phone": None, "status": "login_failed", "error": login_error})
        else:
            items.append({**item, "phone": phone, "status": "ok"})

    valid_count = sum(1 for i in items if i["status"] == "ok")

    BATCH["items"] = items
    BATCH["index"] = -1
    BATCH["success"] = 0
    BATCH["failed"] = total - valid_count
    BATCH["active"] = True

    await status.edit_text(f"📦 Found **{total}** session(s) in the zip — **{valid_count}** valid.", parse_mode="Markdown")
    await send_next_batch_item(message.chat.id)


async def send_next_batch_item(chat_id: int):
    items = BATCH["items"]
    idx = BATCH["index"] + 1

    # Skip invalid / login-failed entries automatically (already counted in
    # BATCH["failed"]) — only valid, logged-in accounts get shown.
    while idx < len(items) and items[idx]["status"] != "ok":
        idx += 1
    BATCH["index"] = idx

    if idx >= len(items):
        BATCH["active"] = False
        await bot.send_message(
            chat_id,
            f"🏁 All done!\n\n✅ Successful: {BATCH['success']}\n❌ Failed: {BATCH['failed']}"
        )
        return

    item = items[idx]
    account_id = gen_account_id()
    ACCOUNTS[account_id] = {"session": item["session"], "phone": item["phone"]}
    item["account_id"] = account_id
    BATCH["success"] += 1

    has_more = any(i["status"] == "ok" for i in items[idx + 1:])
    await bot.send_message(
        chat_id,
        f"📱 Number: `{item['phone']}`",
        parse_mode="Markdown",
        reply_markup=account_kb(account_id, with_next=has_more)
    )


@dp.callback_query(F.data == "batch_next")
async def batch_next_handler(callback: types.CallbackQuery):
    if not is_owner(callback.from_user.id):
        return
    await callback.answer()
    if not BATCH["active"]:
        await callback.message.answer("ℹ️ No active batch right now.")
        return
    await send_next_batch_item(callback.message.chat.id)


# ---------------------------------------------------------------------------
# Check OTP — on-demand only, never auto / background
# ---------------------------------------------------------------------------

@dp.callback_query(F.data.startswith("checkotp_"))
async def check_otp_handler(callback: types.CallbackQuery):
    if not is_owner(callback.from_user.id):
        return

    account_id = callback.data.split("_", 1)[1]
    account = ACCOUNTS.get(account_id)
    if not account:
        await callback.answer("❌ This session is no longer available.", show_alert=True)
        return

    await callback.answer("🔍 Checking...")

    client = TelegramClient(StringSession(account["session"]), API_ID, API_HASH)
    try:
        await client.connect()
        messages = await client.get_messages(TELEGRAM_SERVICE_ID, limit=5)
        otp = None
        for m in messages:
            if m.text:
                match = OTP_CODE_RE.search(m.text)
                if match:
                    otp = match.group(1)
                    break

        if otp:
            await callback.message.reply(otp)
        else:
            await callback.message.reply("❌ No recent OTP found.")
    except Exception as e:
        # Reporting only — the session itself is left completely untouched.
        await callback.message.reply(f"❌ Could not fetch OTP.\n\nReason: {e}")
    finally:
        # Only disconnects THIS on-demand connection. Never client.log_out() —
        # the account's session must survive a failed check.
        await client.disconnect()


async def main():
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
