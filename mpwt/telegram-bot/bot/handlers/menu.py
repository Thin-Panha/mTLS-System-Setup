"""
menu.py — top-level handler for pinned panel buttons.

Registered in app.py as a bare CallbackQueryHandler (group 0, outside any
ConversationHandler) so panel buttons always work regardless of state.

Every tap:
  1. Sync server + update panel counts in-place
  2. Send NEW message for the sub-flow
"""

import logging
import requests
from telegram import Update
from telegram.ext import ContextTypes

from utils.auth import restricted
from utils.panel import sync_and_update_panel

logger = logging.getLogger(__name__)

CB_GUIDELINE = "menu:guideline"
CB_CSR       = "menu:csr"


@restricted
async def handle_panel_button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    bot     = context.bot
    chat_id = update.effective_chat.id

    # Sync + refresh panel counts
    try:
        pending, _, _ = await sync_and_update_panel(bot, chat_id)
    except requests.RequestException as e:
        logger.error("handle_panel_button: server unreachable: %s", e)
        await query.message.reply_text(
            "⚠️ Could not reach the enrollment server\\. Please try again\\.",
            parse_mode="MarkdownV2",
        )
        return

    context.user_data["pending_devices"] = pending

    if query.data == CB_GUIDELINE:
        from bot.handlers.guideline import start_guideline
        await start_guideline(update, context)

    elif query.data == CB_CSR:
        from bot.handlers.submit_csr import start_submit_csr
        await start_submit_csr(update, context)
