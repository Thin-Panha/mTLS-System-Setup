"""
Whitelist enforcement with hot-reload, rate limiting, and persistent blocking.

Whitelist file (whitelist.txt):
  - Read on every gated update — no restart needed to add/remove users
  - Format: TELEGRAM_ID    EMPLOYEE_NAME   (space/tab separated)
  - Lines starting with # are comments, blank lines ignored
  - If file is missing or empty → deny all, but still log who tried
  - Leading-zero IDs are rejected (never auto-corrected), one-time warning
  - Missing employee name produces a one-time reminder in logs

Log behavior:
  - All warnings fire ONCE per unique issue, never repeated
  - Authorized: logs user_id + Telegram username + whitelist name
  - Unauthorized: logs user_id + Telegram username + attempt count
  - Blocked: silent drop, zero logging

Rate limiting (unauthorized users only):
  - Attempts 1 to MAX_ATTEMPTS-1 : logged as WARNING, silently ignored
  - Attempt MAX_ATTEMPTS          : logged as BLOCKING, added to block dict
  - Attempts while blocked        : if still not in whitelist, silent drop
  - Block expires after BLOCK_DURATION seconds → tracking resets

Authorized users are NEVER rate limited or blocked.
Adding an ID to whitelist.txt immediately unblocks the user on their next
checked update. Removing an ID immediately cuts off access on the next
update too — enforced globally via enforce_whitelist_gate(), not just /start.
Bot restart clears all blocks (in-memory).

Enforcement is two-layered:
  1. enforce_whitelist_gate — registered at handler group=-1 in bot/app.py,
     runs before EVERY update (commands, button taps, file uploads, plain
     text) so a removed user is cut off on their very next interaction.
  2. restricted — optional decorator kept for any standalone handler you
     want to gate individually outside the global flow.
"""

import logging
import os
import time
from collections import defaultdict
from functools import wraps

from telegram import Update
from telegram.ext import ApplicationHandlerStop, ContextTypes

from config.settings import settings

logger = logging.getLogger(__name__)

# ── In-memory state ────────────────────────────────────────────────────────────
_attempt_times: dict[int, list[float]] = defaultdict(list)
_blocked_until: dict[int, float]       = {}
_warned_once: set[str] = set()


def _warn_once(key: str, message: str, *args) -> None:
    if key not in _warned_once:
        logger.warning(message, *args)
        _warned_once.add(key)


def _load_whitelist() -> dict[int, str]:
    """Read whitelist.txt and return {telegram_id: employee_name}."""
    path = settings.WHITELIST_PATH

    if not os.path.exists(path):
        _warn_once(
            "file_missing",
            "Whitelist file not found at %s — denying all access", path,
        )
        return {}

    whitelist: dict[int, str] = {}

    with open(path, encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            parts  = line.split(None, 1)
            id_str = parts[0]
            name   = parts[1].strip() if len(parts) == 2 else ""

            if not id_str.isdigit():
                _warn_once(
                    f"invalid_id_line_{lineno}",
                    "whitelist.txt line %d: invalid ID %r — skipping",
                    lineno, id_str,
                )
                continue

            if id_str.startswith("0") and id_str != "0":
                _warn_once(
                    f"leading_zero_line_{lineno}",
                    "whitelist.txt line %d: ID %r has a leading zero — "
                    "skipping (fix or remove this line in whitelist.txt)",
                    lineno, id_str,
                )
                continue

            if not name:
                _warn_once(
                    f"no_name_line_{lineno}",
                    "whitelist.txt line %d: ID %r has no employee name — "
                    "add a name after the ID for better audit logs",
                    lineno, id_str,
                )
                name = "(no name)"

            whitelist[int(id_str)] = name

    logger.debug("Whitelist loaded: %d authorized users", len(whitelist))
    return whitelist


async def _check_and_track(update: Update) -> bool:
    """
    Single source of truth for authorization + rate-limit/block tracking.
    Used by both enforce_whitelist_gate and the restricted decorator, so
    behavior/logging is identical regardless of which one fires.
    """
    user    = update.effective_user
    user_id = user.id if user else None
    now     = time.monotonic()

    whitelist = _load_whitelist()

    if whitelist and user_id in whitelist:
        if user_id in _blocked_until:
            logger.info(
                "User user_id=%s username=@%s name=%s was blocked but is "
                "now in whitelist — clearing block",
                user_id, user.username if user.username else "no_username",
                whitelist[user_id],
            )
            del _blocked_until[user_id]
            _attempt_times[user_id].clear()

        logger.info(
            "Authorized access — user_id=%s username=@%s name=%s",
            user_id, user.username if user.username else "no_username",
            whitelist[user_id],
        )
        return True

    # Unauthorized — includes users who WERE authorized and just got removed
    if user_id in _blocked_until:
        if now < _blocked_until[user_id]:
            return False  # still blocked — silent drop, zero logging
        else:
            del _blocked_until[user_id]
            _attempt_times[user_id].clear()
            logger.info(
                "Block expired — user_id=%s username=@%s resuming tracking",
                user_id, user.username if user.username else "no_username",
            )

    if not whitelist:
        _warn_once(
            "whitelist_empty",
            "Whitelist is empty — denying all access. "
            "Add Telegram IDs to %s to allow users.",
            settings.WHITELIST_PATH,
        )

    window_start = now - settings.RATE_WINDOW_SECONDS
    attempts     = _attempt_times[user_id]
    attempts[:]  = [t for t in attempts if t > window_start]
    attempts.append(now)
    count = len(attempts)

    if count >= settings.RATE_MAX_ATTEMPTS:
        _blocked_until[user_id] = now + settings.RATE_BLOCK_DURATION
        logger.warning(
            "BLOCKING user_id=%s username=@%s for %ds after %d attempts in %ds window",
            user_id, user.username if user.username else "no_username",
            settings.RATE_BLOCK_DURATION, count, settings.RATE_WINDOW_SECONDS,
        )
        return False

    logger.warning(
        "Unauthorized attempt %d/%d — user_id=%s username=@%s",
        count, settings.RATE_MAX_ATTEMPTS, user_id,
        user.username if user.username else "no_username",
    )
    return False


def restricted(func):
    """Optional per-handler gate — not required for the main flow anymore."""
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        if await _check_and_track(update):
            return await func(update, context, *args, **kwargs)
        return
    return wrapper


async def enforce_whitelist_gate(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Global gate — registered at group=-1 in bot/app.py. Runs before EVERY
    update regardless of ConversationHandler state, so a user removed from
    whitelist.txt is cut off on their very next tap/message/file upload.
    """
    if await _check_and_track(update):
        return  # authorized → let the ConversationHandler process it

    if update.callback_query:
        try:
            await update.callback_query.answer()  # clear the spinner, no popup
        except Exception:
            pass

    raise ApplicationHandlerStop
