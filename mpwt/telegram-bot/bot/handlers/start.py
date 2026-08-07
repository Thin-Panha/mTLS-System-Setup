"""
Handlers: /start  /cancel  handle_main_menu  handle_menu_interrupt  handle_unexpected

Dedup strategy:
  - asyncio.Lock  : prevents concurrent execution of the same handler
                    for the same user (e.g. two updates processed in parallel).
  - Cooldown dict : prevents the same menu button from firing twice in quick
                    succession even when the updates arrive sequentially
                    (lock already released before the second update is dispatched).
                    A 1.5 s window is enough to swallow Telegram retries without
                    annoying a real second tap.
"""

import asyncio
import logging
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import requests
from telegram import Update, ReplyKeyboardMarkup, ReplyKeyboardRemove, KeyboardButton
from telegram.ext import ContextTypes, ConversationHandler

from bot.states import STATE_MAIN_MENU
#from utils.auth import restricted, _load_whitelist
from utils.auth import _load_whitelist
from utils.api import fetch_pending_devices
from utils.state_store import (
    get_guideline_sent, sync_with_server, get_expired_devices, clear_expired,
)
from utils.markdown import esc

logger = logging.getLogger(__name__)

BTN_GUIDELINE = "📋 Request Guideline"
BTN_CSR       = "📤 Submit CSR"
BTN_CANCEL    = "❌ Cancel"

# ── Dedup helpers ──────────────────────────────────────────────────────────────

_user_locks: dict[int, asyncio.Lock] = {}
# Maps user_id -> (button_text, timestamp) of last handled menu tap
_last_menu_tap: dict[int, tuple[str, float]] = {}
_COOLDOWN_SECS = 1.5


def _get_lock(user_id: int) -> asyncio.Lock:
    if user_id not in _user_locks:
        _user_locks[user_id] = asyncio.Lock()
    return _user_locks[user_id]


def _is_duplicate_tap(user_id: int, text: str) -> bool:
    """Return True if the same button was handled within the cooldown window."""
    entry = _last_menu_tap.get(user_id)
    if entry and entry[0] == text and (time.monotonic() - entry[1]) < _COOLDOWN_SECS:
        return True
    _last_menu_tap[user_id] = (text, time.monotonic())
    return False


# ── Expiry helpers (same logic as guideline.py / submit_csr.py) ────────────────

def _parse_expiry(value: str):
    """Parse an RFC 1123 HTTP-date (Flask's default JSON datetime format), or None."""
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _is_expired(token_expires: str) -> bool:
    dt = _parse_expiry(token_expires)
    if dt is None:
        return False
    return dt <= datetime.now(dt.tzinfo)


# ── Keyboard / menu text ───────────────────────────────────────────────────────

def _main_menu_keyboard() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        [
            [KeyboardButton(BTN_GUIDELINE)],
            [KeyboardButton(BTN_CSR)],
            [KeyboardButton(BTN_CANCEL)],
        ],
        resize_keyboard=True,
        one_time_keyboard=False,
        input_field_placeholder="Choose an option…",
    )


def _build_menu_text(pending: list[dict]) -> str:
    """Build the admin panel status text from a live device list."""
    guideline_sent = get_guideline_sent()
    sent_ids       = {int(k) for k in guideline_sent.keys()}
    pending_ids    = {d["id"] for d in pending}

    # Same still-expired resolution as guideline.py / submit_csr.py, so the
    # panel text can never disagree with what those flows actually show.
    expired_map   = get_expired_devices()
    still_expired = set()
    for d in pending:
        if str(d["id"]) in expired_map:
            if _is_expired(d.get("token_expires", "")):
                still_expired.add(d["id"])
            else:
                clear_expired(d["id"])

    n_new = len([
        d for d in pending
        if d["id"] not in sent_ids and d["id"] not in still_expired and not d.get("reenroll")
    ])
    n_reenroll = len([
        d for d in pending
        if d["id"] not in sent_ids and d["id"] not in still_expired and d.get("reenroll")
    ])
    n_guide   = n_new + n_reenroll
    n_waiting = len((sent_ids & pending_ids) - still_expired)

    lines = ["🔐 *MPWT Enrollment Bot — Admin Panel*\n"]

    if n_guide == 0:
        lines.append("📋 Request Guideline   — *0* pending")
    elif n_new > 0 and n_reenroll > 0:
        lines.append(
            f"📋 Request Guideline   — *{n_guide}* pending "
            f"\\(*{n_new}* new, *{n_reenroll}* re\\-enroll\\)"
        )
    elif n_new > 0:
        lines.append(f"📋 Request Guideline   — *{n_new}* new pending")
    else:
        lines.append(f"📋 Request Guideline   — *{n_reenroll}* re\\-enroll pending")

    lines.append(f"📤 Submit CSR          — *{n_waiting}* waiting")
    lines.append("\nChoose an option from the menu below:")
    return "\n".join(lines)


# ── /start ─────────────────────────────────────────────────────────────────────

#@restricted
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    lock    = _get_lock(user_id)

    if lock.locked():
        return  # already handling a /start for this user

    async with lock:
        # Clear any in-progress sub-flow state immediately so stale data
        # cannot leak into the fresh panel or sub-flow handlers.
        context.user_data.clear()

        try:
            pending = fetch_pending_devices()
        except requests.RequestException as e:
            logger.error("cmd_start: failed to fetch devices: %s", e)
            await update.message.reply_text(
                "⚠️ Could not reach the enrollment server\\. Please try again\\.",
                parse_mode="MarkdownV2",
            )
            return ConversationHandler.END

        pending_ids = {d["id"] for d in pending}
        removed     = sync_with_server(pending_ids)

        if removed:
            lines = "\n".join(
                f"  • {esc(r['full_name'])} \\({esc(r['employee_id'])}\\) — Device {r['device_id']}"
                for r in removed
            )
            noun = "entry" if len(removed) == 1 else "entries"
            await update.message.reply_text(
                f"ℹ️ {len(removed)} {noun} auto\\-removed \\(no longer actionable\\):\n{lines}",
                parse_mode="MarkdownV2",
            )

        context.user_data["pending_devices"] = pending

        # Reset cooldown so the first tap after /start is never suppressed.
        _last_menu_tap.pop(user_id, None)

        await update.message.reply_text(
            _build_menu_text(pending),
            parse_mode="MarkdownV2",
            reply_markup=_main_menu_keyboard(),
        )
        return STATE_MAIN_MENU


# ── Main-menu handler (STATE_MAIN_MENU) ────────────────────────────────────────

async def handle_main_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    lock    = _get_lock(user_id)
    text    = (update.message.text or "").strip()

    if lock.locked():
        return STATE_MAIN_MENU

    if _is_duplicate_tap(user_id, text):
        logger.debug("handle_main_menu: duplicate tap suppressed for user=%s btn=%r", user_id, text)
        return STATE_MAIN_MENU

    async with lock:
        if text == BTN_CANCEL:
            await update.message.reply_text(
                "Cancelled\\. Send /start to open the admin panel\\.",
                parse_mode="MarkdownV2",
                reply_markup=ReplyKeyboardRemove(),
            )
            context.user_data.clear()
            return ConversationHandler.END

        if text == BTN_GUIDELINE:
            from bot.handlers.guideline import start_guideline
            return await start_guideline(update, context)

        if text == BTN_CSR:
            from bot.handlers.submit_csr import start_submit_csr
            return await start_submit_csr(update, context)

        await update.message.reply_text(
            "Please choose an option from the menu below\\.",
            parse_mode="MarkdownV2",
            reply_markup=_main_menu_keyboard(),
        )
        return STATE_MAIN_MENU


# ── Menu-interrupt handler (all sub-flow states) ───────────────────────────────

async def handle_menu_interrupt(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Admin pressed a menu button while inside a sub-flow.

    Behavior:
      📋 Request Guideline -> immediately restart guideline flow
      📤 Submit CSR       -> immediately restart CSR flow
      ❌ Cancel           -> end conversation
    """

    user_id = update.effective_user.id
    lock    = _get_lock(user_id)
    text    = (update.message.text or "").strip()

    if lock.locked():
        return

    if _is_duplicate_tap(user_id, text):
        logger.debug(
            "handle_menu_interrupt: duplicate tap suppressed for user=%s btn=%r",
            user_id,
            text,
        )
        return STATE_MAIN_MENU

    async with lock:
        # Reset current flow completely
        context.user_data.clear()

        if text == BTN_CANCEL:
            await update.message.reply_text(
                "Cancelled\\. Send /start to open the admin panel\\.",
                parse_mode="MarkdownV2",
                reply_markup=ReplyKeyboardRemove(),
            )
            return ConversationHandler.END

        #
        # 📋 Request Guideline
        #
        if text == BTN_GUIDELINE:
            try:
                pending = fetch_pending_devices()
                context.user_data["pending_devices"] = pending
            except requests.RequestException as e:
                logger.error(
                    "handle_menu_interrupt guideline: fetch failed: %s",
                    e,
                )
                await update.message.reply_text(
                    "⚠️ Could not reach the enrollment server\\. Please try again\\.",
                    parse_mode="MarkdownV2",
                )
                return ConversationHandler.END

            from bot.handlers.guideline import start_guideline
            return await start_guideline(update, context)

        #
        # 📤 Submit CSR
        #
        if text == BTN_CSR:
            try:
                pending = fetch_pending_devices()
                context.user_data["pending_devices"] = pending
            except requests.RequestException as e:
                logger.error(
                    "handle_menu_interrupt csr: fetch failed: %s",
                    e,
                )
                await update.message.reply_text(
                    "⚠️ Could not reach the enrollment server\\. Please try again\\.",
                    parse_mode="MarkdownV2",
                )
                return ConversationHandler.END

            from bot.handlers.submit_csr import start_submit_csr
            return await start_submit_csr(update, context)

        return STATE_MAIN_MENU

# ── /cancel ────────────────────────────────────────────────────────────────────

async def cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.clear()
    await update.message.reply_text(
        "Cancelled\\. Send /start to open the admin panel\\.",
        parse_mode="MarkdownV2",
        reply_markup=ReplyKeyboardRemove(),
    )
    return ConversationHandler.END


# ── Fallback: unexpected input ─────────────────────────────────────────────────

async def handle_unexpected(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return
    text = update.message.text or ""
    if text.startswith("/start") or text in (BTN_GUIDELINE, BTN_CSR, BTN_CANCEL):
        return

    user_id   = update.effective_user.id if update.effective_user else None
    whitelist = _load_whitelist()
    if not whitelist or user_id not in whitelist:
        return

    await update.message.reply_text(
        "ℹ️ *How to use this bot:*\n\n"
        "1️⃣ /start → opens admin panel\n"
        "2️⃣ 📋 Request Guideline\n"
        "    → pick employee → bot sends config file \\+ command\n"
        "    → forward these to the employee\n"
        "3️⃣ Wait for employee to send back their \\.csr file\n"
        "4️⃣ /start → 📤 Submit CSR\n"
        "    → pick same employee → upload their \\.csr file\n"
        "5️⃣ Bot issues certificate\n"
        "    → forward certificate \\+ install instructions to employee\n\n"
        "Send /start to begin\\.",
        parse_mode="MarkdownV2",
    )
