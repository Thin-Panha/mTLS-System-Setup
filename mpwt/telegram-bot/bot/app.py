"""
Application factory — builds the Telegram Application and registers handlers.

Key architecture decisions:
  - Main menu is a persistent ReplyKeyboardMarkup (bottom bar).
  - STATE_MAIN_MENU handled by MessageHandler (text).
  - Every OTHER state also handles the menu text buttons so pressing them
    during a sub-flow cleanly cancels and re-routes, instead of falling
    through to the fallback handle_unexpected.
  - Sub-flow selections (device pick, OS pick, etc.) use InlineKeyboardMarkup
    + CallbackQueryHandler — unchanged.
  - /start is in BOTH entry_points and fallbacks so it always resets.
"""

import logging

from telegram import Update
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ConversationHandler,
    MessageHandler,
    TypeHandler,
    filters,
)
from utils.auth import enforce_whitelist_gate

from telegram.request import HTTPXRequest

from config.settings import settings
from bot.states import (
    STATE_MAIN_MENU,
    STATE_TOKEN_PICK,
    STATE_OS_PICK,
    STATE_CSR_PICK,
    STATE_AWAIT_CSR,
    STATE_CSR_CONFIRM,
)
from bot.handlers.start import (
    cmd_start, cmd_cancel, handle_main_menu, handle_menu_interrupt,
    handle_unexpected, BTN_GUIDELINE, BTN_CSR, BTN_CANCEL,
)
from bot.handlers.guideline  import handle_device_pick, handle_os_pick
from bot.handlers.submit_csr import handle_employee_pick
from bot.handlers.csr        import handle_csr_file, handle_csr_text, handle_csr_confirm

logger = logging.getLogger(__name__)

# Matches any of the three persistent menu button labels
_MENU_FILTER = filters.Regex(
    rf"^({BTN_GUIDELINE}|{BTN_CSR}|{BTN_CANCEL})$"
)


def create_app() -> Application:
    request = HTTPXRequest(
        connect_timeout=20,
        read_timeout=120,
        write_timeout=120,
        pool_timeout=60,
    )

    app = (
        Application.builder()
        .token(settings.TELEGRAM_TOKEN)
        .request(request)
        .build()
    )

    conv = ConversationHandler(
        entry_points=[
            CommandHandler("start", cmd_start),
        ],
        states={
            # ── Main menu ──────────────────────────────────────────────────
            STATE_MAIN_MENU: [
                MessageHandler(_MENU_FILTER, handle_main_menu),
            ],

            # ── Guideline: pick employee ───────────────────────────────────
            # Menu buttons here cancel the sub-flow and re-route
            STATE_TOKEN_PICK: [
                CallbackQueryHandler(handle_device_pick, pattern=r"^guide:dev:"),
                CallbackQueryHandler(handle_device_pick, pattern=r"^guide:back$"),
                MessageHandler(_MENU_FILTER, handle_menu_interrupt),
            ],

            # ── Guideline: pick OS ─────────────────────────────────────────
            STATE_OS_PICK: [
                CallbackQueryHandler(handle_os_pick, pattern=r"^guide:os:"),
                MessageHandler(_MENU_FILTER, handle_menu_interrupt),
            ],

            # ── Submit CSR: pick employee ──────────────────────────────────
            STATE_CSR_PICK: [
                CallbackQueryHandler(handle_employee_pick, pattern=r"^csr:emp:"),
                CallbackQueryHandler(handle_employee_pick, pattern=r"^csr:back$"),
                MessageHandler(_MENU_FILTER, handle_menu_interrupt),
            ],

            # ── Submit CSR: upload .csr file ───────────────────────────────
            STATE_AWAIT_CSR: [
                MessageHandler(filters.Document.ALL, handle_csr_file),
                # Menu buttons take priority over plain text in this state
                MessageHandler(_MENU_FILTER, handle_menu_interrupt),
                MessageHandler(filters.TEXT & ~filters.COMMAND, handle_csr_text),
            ],

            # ── Submit CSR: filename mismatch confirm ──────────────────────
            STATE_CSR_CONFIRM: [
                CallbackQueryHandler(handle_csr_confirm, pattern=r"^csr:(submit_anyway|reupload)$"),
                MessageHandler(_MENU_FILTER, handle_menu_interrupt),
            ],
        },
        fallbacks=[
            # /start in fallbacks guarantees reset from any dead/stuck state
            CommandHandler("start", cmd_start),
            CommandHandler("cancel", cmd_cancel),
            MessageHandler(filters.ALL, handle_unexpected),
        ],
        allow_reentry=True,
    )

    app.add_handler(TypeHandler(Update, enforce_whitelist_gate), group=-1)

    app.add_handler(conv)
    logger.info("MPWT Enrollment Bot starting (Admin Panel — Server-Synced Flow)…")
    return app
