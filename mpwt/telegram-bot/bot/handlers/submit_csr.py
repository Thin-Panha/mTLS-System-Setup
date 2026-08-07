"""
Handlers: Flow 2 — Submit CSR (selection step)

Accepts both PENDING and REVOKED+UNUSED devices for CSR submission.
The status check before entering STATE_AWAIT_CSR now allows REVOKED
(since the device was revoked but has a valid new token).
Always fetches live from server.
"""

import logging
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import requests
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes, ConversationHandler
from telegram import ReplyKeyboardRemove

from bot.states import STATE_MAIN_MENU, STATE_CSR_PICK, STATE_AWAIT_CSR
from utils.api import fetch_pending_devices, fetch_device_status
from utils.state_store import (
    get_guideline_sent, remove_device, sync_with_server,
    mark_expired, get_expired_devices, clear_expired,
)
from utils.markdown import esc

logger = logging.getLogger(__name__)

CB_PICK_EMPLOYEE = "csr:emp:"
CB_BACK          = "csr:back"

# Statuses that mean "this device still needs a CSR submission"
_VALID_STATUSES = {"PENDING", "REVOKED"}


async def start_submit_csr(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Live fetch, then show employees awaiting CSR upload."""
    try:
        pending = fetch_pending_devices()
    except requests.RequestException as e:
        logger.error("start_submit_csr: fetch failed: %s", e)
        await update.message.reply_text(
            "⚠️ Could not reach the enrollment server\\. Please try again\\.",
            parse_mode="MarkdownV2",
        )
        return STATE_MAIN_MENU

    pending_ids = {d["id"] for d in pending}
    removed     = sync_with_server(pending_ids)

    if removed:
        lines = "\n".join(
            f"  • {esc(r['full_name'])} \\({esc(r['employee_id'])}\\) — Device {r['device_id']}"
            for r in removed
        )
        await update.message.reply_text(
            f"ℹ️ Auto\\-removed \\(no longer actionable\\):\n{lines}",
            parse_mode="MarkdownV2",
        )

    context.user_data["pending_devices"] = pending

    guideline_sent = get_guideline_sent()

    expired_map   = get_expired_devices()
    pending_by_id = {d["id"]: d for d in pending}
    still_expired = set()
    for dev_id_str in expired_map:
        dev_id = int(dev_id_str)
        dev    = pending_by_id.get(dev_id)
        if dev is None:
            continue
        if _is_expired(dev.get("token_expires", "")):
            still_expired.add(dev_id)
        else:
            clear_expired(dev_id)

    waiting = {
        dev_id: entry
        for dev_id_str, entry in guideline_sent.items()
        if (dev_id := int(dev_id_str)) in pending_ids and dev_id not in still_expired
    }

    if not waiting:
        await update.message.reply_text(
            "⚠️ *No pending CSR submissions\\.*\n\n"
            "No employees are currently waiting for CSR submission\\.\n"
            "Use 📋 Request Guideline first, then wait for\n"
            "the employee to send back their \\.csr file\\.",
            parse_mode="MarkdownV2",
        )
        return STATE_MAIN_MENU

    # Find reenroll flag for each waiting device from the live pending list
    pending_map = {d["id"]: d for d in pending}

    keyboard = []
    csr_list = []
    for i, (dev_id, entry) in enumerate(waiting.items(), start=1):
        os_label   = entry.get("os_type", "?").capitalize()
        reenroll   = pending_map.get(dev_id, {}).get("reenroll", False)
        device_num = pending_map.get(dev_id, {}).get("device_number", "?")  # ← was dev_id

        tag   = " 🔄" if reenroll else ""
        label = (f"[{i}] {entry.get('full_name','?')} "
                 f"({entry.get('employee_id','?')}) · Device {device_num} · {os_label}{tag}")

        keyboard.append([InlineKeyboardButton(
            label, callback_data=f"{CB_PICK_EMPLOYEE}{dev_id}"
        )])
        csr_list.append((dev_id, entry))

    keyboard.append([InlineKeyboardButton("⬅️ Back", callback_data=CB_BACK)])
    context.user_data["csr_waiting"]     = {str(d): e for d, e in csr_list}
    context.user_data["csr_pending_map"] = {str(d["id"]): d for d in pending}


    await update.message.reply_text(
        "📤 *Select employee whose CSR you are submitting:*\n"
        "_\\(🔄 \\= re\\-enrollment\\)_\n\n",
        parse_mode="MarkdownV2",
        reply_markup=InlineKeyboardMarkup(keyboard),
    )
    return STATE_CSR_PICK

async def handle_employee_pick(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    if query.data == CB_BACK:
        await query.edit_message_text(
            "Returned\\. Use the menu below\\.", parse_mode="MarkdownV2"
        )
        return STATE_MAIN_MENU

    device_id_str = query.data[len(CB_PICK_EMPLOYEE):]
    waiting       = context.user_data.get("csr_waiting", {})
    entry         = waiting.get(device_id_str)

    if not entry:
        await query.edit_message_text(
            "⚠️ Selection not found\\. Send /start to refresh\\.",
            parse_mode="MarkdownV2",
            reply_markup=ReplyKeyboardRemove(),
        )
        return ConversationHandler.END

    device_id   = int(device_id_str)
    full_name   = entry.get("full_name",   "?")
    emp_id      = entry.get("employee_id", "?")
    os_type     = entry.get("os_type",     "?")
    file_suffix = entry.get("file_suffix", "")
    reenroll    = context.user_data.get("csr_pending_map", {}).get(device_id_str, {}).get("reenroll", False)
    device_num  = context.user_data.get("csr_pending_map", {}).get(device_id_str, {}).get("device_number", device_id)

    # ── Status check: PENDING is new enroll, REVOKED is re-enroll ─────────
    try:
        current_status = fetch_device_status(device_id)
    except requests.RequestException as e:
        logger.error("handle_employee_pick: status check failed: %s", e)
        await query.edit_message_text(
            "⚠️ Could not verify device status\\. Please try again\\.",
            parse_mode="MarkdownV2",
            reply_markup=ReplyKeyboardRemove(),
        )
        return STATE_CSR_PICK

    if current_status not in _VALID_STATUSES:
        remove_device(device_id)
        await query.edit_message_text(
            f"⚠️ *{esc(full_name)}'s device status changed* — "
            f"no longer actionable \\({esc(current_status or 'unknown')}\\)\\.\n"
            "Removed from list\\. Send /start to refresh\\.",
            parse_mode="MarkdownV2",
            reply_markup=ReplyKeyboardRemove(),
        )
        return ConversationHandler.END

    context.user_data["csr_device_id"]     = device_id
    context.user_data["csr_device_number"] = device_num
    context.user_data["csr_employee_id"]   = emp_id
    context.user_data["csr_full_name"]     = full_name
    context.user_data["csr_os_type"]       = os_type
    context.user_data["csr_file_suffix"]   = file_suffix
    context.user_data["csr_expected"]      = f"request-{file_suffix}.csr"
    context.user_data["csr_reenroll"]      = reenroll

    token_expires = await _fetch_token_expiry(device_id)

    if _is_expired(token_expires):
        mark_expired(device_id, emp_id, full_name)
        expired_fmt = esc(_fmt_expires(token_expires))
     
        await query.edit_message_text(
            f"⚠️ *Token expired* for {esc(full_name)} \\({esc(emp_id)}\\) — Device {device_num}\n"
            f"Expired: `{expired_fmt}`\n\n"
            "Removed from list\\. Generate a new token and re\\-send the guideline\\.",
            parse_mode="MarkdownV2",
        )

        context.user_data.clear()
        return STATE_MAIN_MENU

    token = await _fetch_token_for_device(device_id)
    if not token:
        await query.edit_message_text(
            "⚠️ Could not retrieve enrollment token for this device\\.\n"
            "The token may have expired\\. Use the CLI to generate a new one\\.",
            parse_mode="MarkdownV2",
        )
        return ConversationHandler.END

    context.user_data["csr_token"] = token

    reenroll_note = " \\(re\\-enrollment\\)" if reenroll else ""
    await query.edit_message_text(
        f"📤 *Submitting CSR for{reenroll_note}:*\n\n"
        f"Name:      {esc(full_name)}\n"
        f"ID:        `{esc(emp_id)}`\n"
        f"Device:    {device_num}\n"
        f"OS:        {esc(os_type.capitalize())}\n"
        f"Expected:  `{esc(f'request-{file_suffix}.csr')}`\n\n"
        f"Upload the \\.csr file received from {esc(full_name)} 👇",
        parse_mode="MarkdownV2",
    )
    return STATE_AWAIT_CSR


async def _fetch_token_for_device(device_id: int) -> str:
    from utils.api import api_call
    try:
        resp = api_call("get", f"/api/devices/{device_id}")
        if resp.status_code == 200:
            return resp.json().get("device", {}).get("enroll_token", "")
    except requests.RequestException as e:
        logger.error("_fetch_token_for_device device=%s: %s", device_id, e)
    return ""


async def _fetch_token_expiry(device_id: int) -> str:
    from utils.api import api_call
    try:
        resp = api_call("get", f"/api/devices/{device_id}")
        if resp.status_code == 200:
            return resp.json().get("device", {}).get("token_expires", "")
    except requests.RequestException as e:
        logger.error("_fetch_token_expiry device=%s: %s", device_id, e)
    return ""


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


def _fmt_expires(value: str) -> str:
    """Format an RFC 1123 HTTP-date for display, e.g. 'Thu, 02 Jul 2026 08:08'."""
    try:
        return value.rsplit(":", 1)[0]  # drop seconds+GMT, keep 'Thu, 02 Jul 2026 08:08'
    except Exception:
        return value or "?"
