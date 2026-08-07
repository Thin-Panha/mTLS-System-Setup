"""
Handlers: CSR upload, validation, enrollment submission, certificate delivery.

This is the admin-facing version: admin uploads the employee's .csr file,
bot submits it to the backend CA, and sends the signed cert back to admin
for forwarding to the employee.

Two-layer protection:
  Layer 1 (bot): filename mismatch warning — admin can override or re-upload
  Layer 2 (backend): HMAC/CN validation — cannot be bypassed

On success:
  - Certificate file sent to admin
  - Install instructions sent to admin
  - Device removed from state.json
  - Admin instructed to forward via secure channel
"""

import logging
import requests
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, ReplyKeyboardRemove
from telegram.ext import ContextTypes, ConversationHandler
from telegram.error import TimedOut, NetworkError

from bot.states import STATE_AWAIT_CSR, STATE_CSR_CONFIRM
from utils.api import api_call
from utils.csr import is_valid_pem_csr, normalize_csr
from utils.state_store import remove_device
from utils.markdown import esc
from utils.install_instructions import get_install_instructions

logger = logging.getLogger(__name__)

CB_SUBMIT_ANYWAY = "csr:submit_anyway"
CB_REUPLOAD      = "csr:reupload"


# ── Public handlers ────────────────────────────────────────────────────────────

async def handle_csr_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin uploads a .csr file as a Telegram attachment."""
    doc = update.message.document

    if doc.file_size > 10_240:
        await update.message.reply_text(
            "❌ That file is too large for a CSR \\(max 10 KB\\)\\.",
            parse_mode="MarkdownV2",
        )
        return STATE_AWAIT_CSR

    try:
        tg_file = await doc.get_file()
        raw     = await tg_file.download_as_bytearray()
    except (TimedOut, NetworkError) as e:
        logger.warning("Telegram file download timed out: %s", e)
        await update.message.reply_text(
            "⚠️ File download timed out\\. Please try again\\.",
            parse_mode="MarkdownV2",
        )
        return STATE_AWAIT_CSR

    try:
        csr_text = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        await update.message.reply_text(
            "❌ Could not read that file as text\\. "
            "Please send the `\\.csr` file directly\\.",
            parse_mode="MarkdownV2",
        )
        return STATE_AWAIT_CSR

    uploaded_filename = doc.file_name or ""
    return await _check_filename_then_process(
        update, context, csr_text, uploaded_filename
    )


async def handle_csr_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin pasted PEM text directly — skip filename check, go straight to validation."""
    return await _process_csr(update, context, update.message.text.strip())


async def handle_csr_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Admin responded to filename mismatch warning.
    CB_SUBMIT_ANYWAY  → submit the cached CSR to backend anyway
    CB_REUPLOAD       → prompt admin to upload again
    """
    query = update.callback_query
    await query.answer()

    if query.data == CB_REUPLOAD:
        await query.edit_message_text(
            "Please upload the correct \\.csr file\\.",
            parse_mode="MarkdownV2",
        )
        return STATE_AWAIT_CSR

    if query.data == CB_SUBMIT_ANYWAY:
        csr_text = context.user_data.get("pending_csr_text", "")
        if not csr_text:
            await query.edit_message_text(
                "⚠️ Cached CSR lost\\. Please upload the file again\\.",
                parse_mode="MarkdownV2",
            )
            return STATE_AWAIT_CSR
        # Use query.message so _process_csr can reply to it
        return await _process_csr(query, context, csr_text, via_query=True)

    return STATE_CSR_CONFIRM


# ── Internal ───────────────────────────────────────────────────────────────────

async def _check_filename_then_process(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    csr_text: str,
    uploaded_filename: str,
):
    """Layer 1: filename check. Warn on mismatch, allow override."""
    expected = context.user_data.get("csr_expected", "")

    if expected and uploaded_filename and uploaded_filename != expected:
        # Store CSR for potential "submit anyway" path
        context.user_data["pending_csr_text"] = csr_text

        emp_id    = context.user_data.get("csr_employee_id", "?")
        dev_num   = context.user_data.get("csr_device_number") \
                    or context.user_data.get("csr_device_id", "?")   # ← fallback if missing
        full_name = context.user_data.get("csr_full_name",   "?")

        await update.message.reply_text(
            "⚠️ *Filename mismatch detected*\n\n"
            f"Selected:  {esc(full_name)} \\({esc(emp_id)}\\) — Device {dev_num}\n"
            f"Expected:  `{esc(expected)}`\n"
            f"Uploaded:  `{esc(uploaded_filename)}`\n\n"
            "This looks like the wrong file\\.",
            parse_mode="MarkdownV2",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("✅ Submit anyway", callback_data=CB_SUBMIT_ANYWAY),
                InlineKeyboardButton("❌ Upload different file", callback_data=CB_REUPLOAD),
            ]]),
        )
        return STATE_CSR_CONFIRM

    return await _process_csr(update, context, csr_text)


async def _process_csr(
    update_or_query,
    context: ContextTypes.DEFAULT_TYPE,
    csr_text: str,
    via_query: bool = False,
):
    """Validate PEM, submit to backend, deliver certificate."""

    async def reply(text, **kwargs):
        if via_query:
            await update_or_query.message.reply_text(text, **kwargs)
        else:
            await update_or_query.message.reply_text(text, **kwargs)

    async def reply_doc(caption=None, **kwargs):
        if caption is not None:
            kwargs["caption"] = caption
            kwargs.setdefault("parse_mode", "MarkdownV2")
        if via_query:
            await update_or_query.message.reply_document(**kwargs)
        else:
            await update_or_query.message.reply_document(**kwargs)

    file_suffix = context.user_data.get("csr_file_suffix", "cert")
    full_name   = context.user_data.get("csr_full_name",   "?")
    emp_id      = context.user_data.get("csr_employee_id", "?")
    device_id   = context.user_data.get("csr_device_id")
    os_type     = context.user_data.get("csr_os_type",     "linux")
    token       = context.user_data.get("csr_token",       "")

    # ── PEM validation ─────────────────────────────────────────────────────
    if not is_valid_pem_csr(csr_text):
        ef = esc(f"request-{file_suffix}.csr")
        await reply(
            f"❌ That doesn't look like a valid CSR\\.\n\n"
            f"Please upload the `{ef}` file received from {esc(full_name)}\\.\n\n"
            "If pasting text, make sure it starts with:\n"
            "`\\-\\-\\-\\-\\-BEGIN CERTIFICATE REQUEST\\-\\-\\-\\-\\-`",
            parse_mode="MarkdownV2",
        )
        return STATE_AWAIT_CSR

    csr_text = normalize_csr(csr_text)

    await reply(
        f"⏳ Submitting CSR for {esc(full_name)} to the MPWT CA\\.\\.\\.",
        parse_mode="MarkdownV2",
    )

    payload = {
        "token":   token,
        "csr":     csr_text,
        "os_type": os_type,
    }

    try:
        resp = api_call("post", "/api/bot/enroll", json=payload)
    except requests.RequestException as e:
        logger.error("enroll network error device=%s: %s", device_id, e)
        await reply(
            "⚠️ Network error contacting enrollment server\\. Please try again\\.",
            parse_mode="MarkdownV2",
        )
        return STATE_AWAIT_CSR

    # ── 410: token already consumed ────────────────────────────────────────
    if resp.status_code == 410:
        remove_device(device_id)
        await reply(
            "ℹ️ This token has already been used\\.\n\n"
            "The device may already be enrolled\\. "
            "Check the server with `mpwt\\-admin info`\\.",
            parse_mode="MarkdownV2",
        )
        context.user_data.clear()
        return ConversationHandler.END

    # ── 422: HMAC / CN mismatch ────────────────────────────────────────────
    if resp.status_code == 422:
        try:
            err_msg = resp.json().get("error", "Validation failed")
        except Exception:
            err_msg = "Validation failed"
        await reply(
            f"❌ *CSR does not match {esc(full_name)} \\({esc(emp_id)}\\)*\n\n"
            f"`{esc(err_msg)}`\n\n"
            "Token is still valid — upload the correct \\.csr file\\.",
            parse_mode="MarkdownV2",
        )
        # Token NOT consumed — stay in upload state so admin can retry
        return STATE_AWAIT_CSR

    # ── Other non-200 ──────────────────────────────────────────────────────
    if resp.status_code != 200:
        try:
            body   = resp.json()
            error  = body.get("error",  f"HTTP {resp.status_code}")
            reason = body.get("reason", "")
        except Exception:
            error  = f"HTTP {resp.status_code}"
            reason = ""

        logger.error(
            "enroll failed status=%s body=%s device=%s",
            resp.status_code, resp.text[:300], device_id,
        )
        msg = f"❌ *Enrollment failed*\n\n*Error:* `{esc(error)}`"
        if reason:
            msg += f"\n\n*Detail:* `{esc(reason)}`"
        msg += (
            "\n\nUpload a corrected `\\.csr` file to try again, "
            "or send /start to cancel\\."
        )
        await reply(msg, parse_mode="MarkdownV2")
        # Do NOT clear user_data — admin needs csr_expected/csr_token/etc. to retry
        return STATE_AWAIT_CSR

    # ── Success ────────────────────────────────────────────────────────────
    try:
        result   = resp.json()
        crt_name = f"client-{file_suffix}.crt"

        # Send certificate file
        caption_text = (
            f"Signed certificate for {esc(full_name)} "
            f"\\({esc(emp_id)}\\) — {esc(crt_name)}"
        )
        await reply_doc(
            document=result["client_crt"].encode(),
            filename=crt_name,
            caption=caption_text,
            parse_mode="MarkdownV2",
        )
        # Send CA chain if present
#        if result.get("ca_chain_crt"):
#            chain_name = f"ca-chain-{file_suffix}.crt"
#            await reply_doc(
#                document=result["ca_chain_crt"].encode(),
#                filename=chain_name,
#                caption=f"CA chain certificate — {chain_name}",
#            )

        # Send install instructions
        await reply(
            get_install_instructions(os_type),
            parse_mode="MarkdownV2",
        )

        serial = esc(result.get("serial", "N/A"))
        await reply(
            f"✅ *Certificate issued for {esc(full_name)}*\n\n"
            f"Serial: `{serial}`\n\n"
            f"📤 Forward the certificate \\+ install instructions to "
            f"{esc(full_name)} via a *secure channel*\\.\n\n"
            "Send /start to return to the admin panel\\.",
            parse_mode="MarkdownV2",
            reply_markup=ReplyKeyboardRemove(),
        )

        logger.info(
            "Certificate issued — employee=%s emp_id=%s device=%s serial=%s",
            full_name, emp_id, device_id, result.get("serial", "?"),
        )

        # Remove from state.json — enrollment complete
        remove_device(device_id)

    except Exception as e:
        logger.exception("Error processing successful enroll response: %s", e)
        await reply(
            "⚠️ Certificate was issued but something went wrong sending the files\\.\n"
            f"Error: `{esc(str(e))}`\n\n"
            "Contact system admin to retrieve the certificate manually\\.",
            parse_mode="MarkdownV2",
        )

    context.user_data.clear()
    return ConversationHandler.END
