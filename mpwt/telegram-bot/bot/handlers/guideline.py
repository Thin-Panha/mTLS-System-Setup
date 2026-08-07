"""
Handlers: Flow 1 — Request Guideline
"""

import logging
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import requests
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes, ConversationHandler
from telegram import ReplyKeyboardRemove

from bot.states import STATE_MAIN_MENU, STATE_TOKEN_PICK, STATE_OS_PICK
from utils.api import api_call, fetch_pending_devices
from utils.state_store import (
    get_guideline_sent, mark_guideline_sent, sync_with_server,
    mark_expired, get_expired_devices, clear_expired,
)
from utils.markdown import esc

logger = logging.getLogger(__name__)

CB_PICK_DEVICE = "guide:dev:"
CB_PICK_OS     = "guide:os:"
CB_BACK        = "guide:back"


async def start_guideline(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Live fetch, then show actionable devices (PENDING + REVOKED+UNUSED)."""
    try:
        pending = fetch_pending_devices()
    except requests.RequestException as e:
        logger.error("start_guideline: fetch failed: %s", e)
        await update.message.reply_text(
            "⚠️ Could not reach the enrollment server\\. Please try again\\.",
            parse_mode="MarkdownV2",
        )
        return STATE_MAIN_MENU

    pending_ids = {d["id"] for d in pending}
    sync_with_server(pending_ids)
    context.user_data["pending_devices"] = pending

    guideline_sent = get_guideline_sent()
    sent_ids       = {int(k) for k in guideline_sent.keys()}

    # Filter out devices already marked expired — unless their token was
    # refreshed since (new token_expires no longer in the past), in which
    # case clear the stale expired-flag so it can show up again.
    expired_map   = get_expired_devices()
    still_expired = set()
    for d in pending:
        if str(d["id"]) in expired_map:
            if _is_expired(d.get("token_expires", "")):
                still_expired.add(d["id"])
            else:
                clear_expired(d["id"])

    new_devices = [
        d for d in pending
        if d["id"] not in sent_ids and d["id"] not in still_expired
    ]

    if not new_devices:
        await update.message.reply_text(
            "✅ *No new enrollment requests\\.*\n\n"
            "All actionable devices already have guides sent\\.\n"
            "Check 📤 Submit CSR, or use `mpwt\\-admin add\\-device` on server\\.",
            parse_mode="MarkdownV2",
        )
        return STATE_MAIN_MENU

    keyboard = []
    for i, dev in enumerate(new_devices, start=1):
        name       = dev.get("full_name") or dev.get("employee_id", "?")
        emp_id     = dev.get("employee_id", "?")
        reenroll   = dev.get("reenroll", False)
        device_num = dev.get("device_number", "?")

        tag   = " 🔄" if reenroll else ""
        label = f"[{i}] {name} ({emp_id}) · Device {device_num}{tag}"

        keyboard.append([InlineKeyboardButton(
            label, callback_data=f"{CB_PICK_DEVICE}{dev['id']}"
        )])

    keyboard.append([InlineKeyboardButton("⬅️ Back", callback_data=CB_BACK)])
    context.user_data["guide_devices"] = {str(d["id"]): d for d in new_devices}

    await update.message.reply_text(
        "📋 *Select employee to send enrollment guide:*\n"
        "_\\(🔄 \\= re\\-enrollment after revoke\\)_\n\n",
        parse_mode="MarkdownV2",
        reply_markup=InlineKeyboardMarkup(keyboard),
    )
    return STATE_TOKEN_PICK


async def handle_device_pick(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    if query.data == CB_BACK:
        await query.edit_message_text(
            "Returned\\. Use the menu below\\.", parse_mode="MarkdownV2"
        )
        return STATE_MAIN_MENU

    device_id_str = query.data[len(CB_PICK_DEVICE):]
    devices       = context.user_data.get("guide_devices", {})
    device        = devices.get(device_id_str)

    if not device:
        await query.edit_message_text(
            "⚠️ Selection not found\\. Send /start to refresh\\.",
            parse_mode="MarkdownV2",
        )
        return ConversationHandler.END

    device_id = device["id"]
    token_expires = await _fetch_token_expiry(device_id)

    if _is_expired(token_expires):
        raw_full_name = device.get("full_name") or device.get("employee_id", "?")
        raw_emp_id    = device.get("employee_id", "?")
        mark_expired(device_id, raw_emp_id, raw_full_name)

        name    = esc(raw_full_name)
        emp_id  = esc(raw_emp_id)
        dev_num = device.get("device_number", "?")
        expired_fmt = esc(_fmt_expires(token_expires))

        await query.edit_message_text(
            f"⚠️ *Token expired* for {name} \\({emp_id}\\) — Device {dev_num}\n"
            f"Expired: `{expired_fmt}`\n\n"
            "Removed from list\\. Generate a new token to re\\-send the guideline\\.",
            parse_mode="MarkdownV2",
        )

        # Stay alive at the main menu state (keyboard from the last /start
        # is still visible/usable) — no extra panel message needed.
        context.user_data.clear()
        return STATE_MAIN_MENU

    context.user_data["guide_device_id"]     = device_id
    # Per-employee device counter (e.g. "Device 1", "Device 2" for that
    # specific employee) -- distinct from the device's internal DB row id,
    # which is unique across *all* employees and shouldn't be shown to users.
    context.user_data["guide_device_number"] = device.get("device_number", "?")
    context.user_data["guide_employee_id"]   = device.get("employee_id", "")
    context.user_data["guide_full_name"]     = device.get("full_name") or device.get("employee_id", "?")
    context.user_data["guide_token"]         = device.get("enroll_token", "")
    context.user_data["guide_reenroll"]      = device.get("reenroll", False)
    name     = esc(context.user_data["guide_full_name"])
    reenroll = device.get("reenroll", False)
    header   = f"Re\\-enrollment for *{name}*" if reenroll else f"What OS is *{name}*'s device running?"

    await query.edit_message_text(
        header,
        parse_mode="MarkdownV2",
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("Windows", callback_data=f"{CB_PICK_OS}{device['id']}:windows"),
            InlineKeyboardButton("macOS",   callback_data=f"{CB_PICK_OS}{device['id']}:macos"),
            InlineKeyboardButton("Linux",   callback_data=f"{CB_PICK_OS}{device['id']}:linux"),
        ]]),
    )
    return STATE_OS_PICK


async def handle_os_pick(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    parts         = query.data[len(CB_PICK_OS):].split(":", 1)
    os_type       = parts[1] if len(parts) == 2 else ""
    device_id     = context.user_data.get("guide_device_id")
    device_number = context.user_data.get("guide_device_number", "?")
    full_name     = context.user_data.get("guide_full_name", "?")
    emp_id        = context.user_data.get("guide_employee_id", "?")
    token         = context.user_data.get("guide_token", "")
    reenroll      = context.user_data.get("guide_reenroll", False)

    if not token:
        await query.edit_message_text(
            "⚠️ Could not retrieve token for this device\\. "
            "Send /start to refresh\\.",
            parse_mode="MarkdownV2",
        )
        return ConversationHandler.END

    await query.edit_message_text(
        f"OS selected: *{esc(os_type.capitalize())}*\n\n"
        "⏳ Generating enrollment config file\\.\\.\\.",
        parse_mode="MarkdownV2",
    )

    try:
        resp = api_call("post", "/api/bot/config-file",
                        json={"token": token, "os_type": os_type})
    except requests.RequestException as e:
        logger.error("config-file network error: %s", e)
        await query.message.reply_text(
            "⚠️ Could not reach the enrollment server\\. Please try again\\.",
            parse_mode="MarkdownV2",
        )
        return STATE_MAIN_MENU

    if resp.status_code != 200:
        logger.error("config-file failed: HTTP %s device=%s body=%s",
                     resp.status_code, device_id, resp.text[:200])
        await query.message.reply_text(
            "❌ Could not generate config file\\. "
            "Check server logs or contact IT admin\\.",
            parse_mode="MarkdownV2",
        )
        return STATE_MAIN_MENU

    cfg          = resp.json()
    filename     = cfg["filename"]
    content      = cfg["content"]
    stem         = filename.rsplit(".", 1)[0]
    file_suffix  = stem[len("mpwt-enroll-"):]
    expected_csr = f"request-{file_suffix}.csr"

    await query.message.reply_document(
        document=content.encode("utf-8"),
        filename=filename,
        caption=(
            f"{'Re-enrollment' if reenroll else 'Enrollment'} config for "
            f"{full_name} ({emp_id}) — Device {device_number}\n"
            "DO NOT edit this file."
        ),
    )

    ef   = esc(filename)
    ecsr = esc(expected_csr)

    reenroll_note = (
        "\n⚠️ *Note:* This is a re\\-enrollment\\. The employee's previous "
        "certificate has been revoked\\. They must run this script to generate "
        "a new certificate request\\.\n"
        if reenroll else ""
    )

    if os_type == "windows":
        step_header = (
            "*One\\-time setup \\(each time before running\\):*\n"
            "1️⃣ Open PowerShell \\(Start menu → type \"PowerShell\"\\) and run:\n"
            "`Set\\-ExecutionPolicy \\-ExecutionPolicy "
            "RemoteSigned \\-Scope CurrentUser`\n"
            "_\\(This runs the policy change in its own process with errors "
            "suppressed, so if your laptop is managed by company policy and "
            "already allows scripts, you won't see a red error — it just "
            "silently has no effect\\.\\)_\n\n"
            "2️⃣ Download `" + ef + "` → Right\\-click on it → *Properties* → check *Unblock* at the "
            "bottom of the General tab → *Apply* → *OK*\n"
            "   \\(or run `Unblock\\-File \\-Path \"path\\\\to\\\\" + ef + "\"` in PowerShell\\)\n"
            f"3️⃣ Right\\-click `{ef}` → *Run with PowerShell*\\.\n"
            "4️⃣ A window will ask you to choose a folder to save the "
            "CSR \\(Desktop by default\\) — pick a location and click *Select "
            "Folder*\\.\n"
            "5️⃣ The script will try to use your device's TPM chip for "
            "the key first; if that isn't possible on this machine, it "
            "automatically retries with a software\\-protected key instead — "
            "no action needed from you either way\\.\n"
            "6️⃣ When it finishes, press *Enter* to close the window\\.\n"
        )
        step_final = f"7️⃣ Send back the file `{ecsr}`"
    elif os_type == "macos":
        step_header = (
            "*One\\-time setup \\(each time before running\\):*\n"
            f"1️⃣ Download `{ef}` to `~/Downloads/`\\.\n"
            "2️⃣ Open Terminal \\(Cmd\\+Space → type \"Terminal\"\\) and run:\n\n"
            f"`cd ~/Downloads && chmod +x {ef} && ./{ef}`\n\n"
            "_\\(Running it this way \\(via Terminal, not double\\-clicking\\) "
            "avoids the macOS Gatekeeper warning that would otherwise appear "
            "for a downloaded, unsigned script\\.\\)_\n"
            "3️⃣ A folder\\-picker dialog opens asking where to save the CSR "
            "\\(Downloads by default\\)\\. Click *Generate CSR* in the "
            "confirmation dialog that follows\\.\n"
            "4️⃣ The script creates the certificate request and "
            "automatically imports the private key into the macOS Keychain — "
            "no action needed from you\\.\n"
            "5️⃣ When the final dialog appears, you can close the "
            "Terminal window\\.\n"
        )
        step_final = f"6️⃣ Send back the file `{ecsr}`"
    else:
        step_header = (
            "*One\\-time setup \\(each time before running\\):*\n"
            f"1️⃣ Download `{ef}` to `~/Downloads/`\\.\n"
            "2️⃣ Open a terminal and run:\n\n"
            f"`cd ~/Downloads && chmod +x {ef} && ./{ef}`\n\n"
            "3️⃣ A folder\\-picker dialog \\(or a text prompt, on minimal "
            "desktops without zenity/kdialog\\) asks where to save the CSR "
            "\\(Downloads by default\\)\\. Confirm to generate\\.\n"
            "4️⃣ The script creates the certificate request\\. If your "
            "system has `secret\\-tool` \\(GNOME Keyring / KWallet\\), the "
            "private key is imported there automatically and the plaintext "
            "copy is shredded\\. Otherwise the key is saved next to the CSR "
            "with restricted permissions, and the script will tell you "
            "exactly where — keep that file safe and do not share it\\.\n"
            "5️⃣ When the final message appears, you can close the "
            "terminal\\.\n\n"
        )
        step_final = f"6️⃣ Send back the file `{ecsr}`"

    await query.message.reply_text(
        f"📋 *Instructions for {esc(full_name)}:*{reenroll_note}\n\n"
        f"{step_header}\n{step_final}",
        parse_mode="MarkdownV2",
    )

    await query.message.reply_text(
        f"📤 *Forward to {esc(full_name)}:*\n\n"
        f"• The `{ef}` file above\n"
        f"• Ask them to send back `{ecsr}`\n\n"
        "When you receive their CSR file, use /start → 📤 Submit CSR\\.",
        parse_mode="MarkdownV2",
    )

    mark_guideline_sent(device_id=device_id, employee_id=emp_id,
                        full_name=full_name, os_type=os_type, file_suffix=file_suffix)
    logger.info("Guideline sent — device=%s employee=%s os=%s reenroll=%s",
                device_id, emp_id, os_type, reenroll)

    await query.message.reply_text(
        "✅ Guide sent and recorded\\. Send /start to return to the admin panel\\.",
        parse_mode="MarkdownV2",
        reply_markup=ReplyKeyboardRemove(),
    )
    context.user_data.clear()
    return ConversationHandler.END


def _fmt_expires(value: str) -> str:
    """Format an RFC 1123 HTTP-date for display, e.g. 'Thu, 02 Jul 2026 08:08'."""
    try:
        return value.rsplit(":", 1)[0]  # drop seconds+GMT, keep 'Thu, 02 Jul 2026 08:08'
    except Exception:
        return value or "?"

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


async def _fetch_token_expiry(device_id: int) -> str:
    try:
        resp = api_call("get", f"/api/devices/{device_id}")
        if resp.status_code == 200:
            return resp.json().get("device", {}).get("token_expires", "")
    except requests.RequestException as e:
        logger.error("_fetch_token_expiry device=%s: %s", device_id, e)
    return ""
