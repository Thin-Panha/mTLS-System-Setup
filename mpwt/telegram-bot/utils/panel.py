"""
panel.py — the one pinned admin panel message.

One message per chat, stored in state.json as pin_chat_id / pin_message_id.
Edited in-place on every /start and after every action completes.
Created fresh if missing or if Telegram rejects the edit (48h limit).
"""

import logging
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import requests
from telegram import Bot, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.error import BadRequest

from utils.api import fetch_pending_devices
from utils.state_store import (
    get_guideline_sent,
    get_pin_ref,
    save_pin_ref,
    clear_pin_ref,
    sync_with_server,
    get_expired_devices,
    clear_expired,
)
from utils.markdown import esc

logger = logging.getLogger(__name__)

CB_GUIDELINE = "menu:guideline"
CB_CSR       = "menu:csr"


def _panel_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[
        InlineKeyboardButton("📋 Request Guideline", callback_data=CB_GUIDELINE),
        InlineKeyboardButton("📤 Submit CSR",        callback_data=CB_CSR),
    ]])


def _panel_text(n_pending: int, n_waiting: int, sync_time: str) -> str:
    return (
        "🔐 *MPWT Enrollment Bot — Admin Panel*\n\n"
        f"📋 Request Guideline     {n_pending} pending\n"
        f"📤 Submit CSR            {n_waiting} waiting\n\n"
        f"_Last sync: {esc(sync_time)}_"
    )


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


async def sync_and_update_panel(bot: Bot, chat_id: int) -> tuple[list[dict], int, int]:
    """
    Full sync cycle + edit pinned panel in-place.

    Returns (pending_devices, n_pending, n_waiting).
    Raises requests.RequestException if server is unreachable.
    """
    pending     = fetch_pending_devices()          # raises on network error
    pending_ids = {d["id"] for d in pending}

    sync_with_server(pending_ids)                  # silent cleanup

    guideline_sent = get_guideline_sent()
    sent_ids       = {int(k) for k in guideline_sent.keys()}

    # Same still-expired resolution as guideline.py / submit_csr.py, so the
    # badge count and the actual flow can never disagree.
    expired_map   = get_expired_devices()
    still_expired = set()
    for d in pending:
        if str(d["id"]) in expired_map:
            if _is_expired(d.get("token_expires", "")):
                still_expired.add(d["id"])
            else:
                clear_expired(d["id"])

    n_pending = len([
        d for d in pending
        if d["id"] not in sent_ids and d["id"] not in still_expired
    ])
    n_waiting = len((sent_ids & pending_ids) - still_expired)

    sync_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    text      = _panel_text(n_pending, n_waiting, sync_time)

    pin_chat_id, pin_msg_id = get_pin_ref()

    if pin_msg_id and pin_chat_id == chat_id:
        try:
            await bot.edit_message_text(
                chat_id      = chat_id,
                message_id   = pin_msg_id,
                text         = text,
                parse_mode   = "MarkdownV2",
                reply_markup = _panel_keyboard(),
            )
            return pending, n_pending, n_waiting
        except BadRequest as e:
            if "message is not modified" in str(e).lower():
                return pending, n_pending, n_waiting
            # Edit window expired or message deleted — recreate
            logger.warning("Panel edit failed (%s) — recreating", e)
            clear_pin_ref()

    # Create new panel
    msg = await bot.send_message(
        chat_id      = chat_id,
        text         = text,
        parse_mode   = "MarkdownV2",
        reply_markup = _panel_keyboard(),
    )
    save_pin_ref(chat_id, msg.message_id)

    try:
        await bot.pin_chat_message(
            chat_id            = chat_id,
            message_id         = msg.message_id,
            disable_notification = True,
        )
    except Exception as e:
        logger.warning("Could not pin panel message: %s", e)

    return pending, n_pending, n_waiting

