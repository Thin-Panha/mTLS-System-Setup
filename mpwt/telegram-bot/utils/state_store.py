"""
state_store.py — persistent guideline_sent tracking.

state.json stores ONLY what the server cannot provide:
  os_type     — admin selected, not stored on server until enrollment
  file_suffix — derived from config filename (e.g. "EMP001-D3")
  sent_at     — timestamp admin sent the enrollment guide

Schema:
{
  "guideline_sent": {
    "<device_id_str>": {
      "employee_id": "EMP001",
      "full_name":   "Thin Panha",
      "os_type":     "linux",
      "file_suffix": "EMP001-D3",
      "sent_at":     "2026-06-25 14:00"
    }
  }
}

All functions are synchronous (called from async handlers via direct call —
no blocking I/O concern at bot scale). File is written atomically via
rename to avoid corruption on crash.
"""

import json
import logging
import os
import tempfile
from datetime import datetime, timezone

from config.settings import settings

logger = logging.getLogger(__name__)


# ── Internal helpers ───────────────────────────────────────────────────────────

def _load_raw() -> dict:
    """Load state.json; return empty structure if missing or corrupt."""
    path = settings.STATE_PATH
    if not os.path.exists(path):
        return {"guideline_sent": {}, "expired_devices": {}}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if "guideline_sent" not in data:
            data["guideline_sent"] = {}
        if "expired_devices" not in data:
            data["expired_devices"] = {}
        return data
    except (json.JSONDecodeError, OSError) as e:
        logger.error("state.json read error (%s) — starting with empty state", e)
        return {"guideline_sent": {}, "expired_devices": {}}

def _save_raw(data: dict) -> None:
    """Write state.json atomically (write temp → rename)."""
    path = settings.STATE_PATH
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    dir_  = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=dir_, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
    except OSError as e:
        logger.error("state.json write error: %s", e)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ── Public API ─────────────────────────────────────────────────────────────────

def get_guideline_sent() -> dict[str, dict]:
    """
    Return the guideline_sent dict keyed by device_id (str).
    """
    return _load_raw()["guideline_sent"]


def mark_guideline_sent(
    device_id:   int,
    employee_id: str,
    full_name:   str,
    os_type:     str,
    file_suffix: str,
) -> None:
    """
    Record that an enrollment guide was sent for this device.
    Called after admin successfully receives the config file.
    """
    data = _load_raw()
    sent_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")

    data["guideline_sent"][str(device_id)] = {
        "employee_id": employee_id,
        "full_name":   full_name,
        "os_type":     os_type,
        "file_suffix": file_suffix,
        "sent_at":     sent_at,
    }
    _save_raw(data)
    logger.info(
        "state: guideline marked sent — device=%s employee=%s os=%s",
        device_id, employee_id, os_type,
    )

def mark_expired(device_id: int, employee_id: str, full_name: str) -> None:
    """
    Record that this device's token was found expired on click.
    Removes it from guideline_sent (if present) and adds it to a
    persisted expired_devices set so pickers can filter it out on
    the next load, instead of it silently reappearing.
    """
    data = _load_raw()
    if "expired_devices" not in data:
        data["expired_devices"] = {}

    data["guideline_sent"].pop(str(device_id), None)
    data["expired_devices"][str(device_id)] = {
        "employee_id": employee_id,
        "full_name":   full_name,
        "marked_at":   datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
    }
    _save_raw(data)
    logger.info("state: marked device=%s expired", device_id)


def get_expired_devices() -> dict[str, dict]:
    """Return the expired_devices dict keyed by device_id (str)."""
    data = _load_raw()
    return data.get("expired_devices", {})


def clear_expired(device_id: int) -> bool:
    """
    Un-mark a device as expired (called when a fresh token is detected
    for a device previously marked expired — e.g. admin reissued it).
    """
    data = _load_raw()
    key  = str(device_id)
    found = key in data.get("expired_devices", {})
    if found:
        del data["expired_devices"][key]
        _save_raw(data)
        logger.info("state: cleared expired flag for device=%s (token refreshed)", device_id)
    return found

def remove_device(device_id: int) -> bool:
    """
    Remove a device from guideline_sent (called after cert issued or on sync).
    Returns True if the entry existed and was removed, False if not found.
    """
    data  = _load_raw()
    key   = str(device_id)
    found = key in data["guideline_sent"]
    if found:
        del data["guideline_sent"][key]
        _save_raw(data)
        logger.info("state: removed device=%s from guideline_sent", device_id)
    return found


def sync_with_server(pending_device_ids: set[int]) -> list[dict]:
    """
    Cross-check state.json against the current server PENDING device list.

    Any device_id in state.json that is NOT in pending_device_ids is
    auto-removed (device became ACTIVE, REVOKED, EXPIRED, or was deleted).

    Returns list of removed entries (for admin notice display):
        [{"device_id": 4, "full_name": "Sok Dara", "employee_id": "EMP002"}, ...]
    """
    data    = _load_raw()
    stored  = data["guideline_sent"]
    removed = []

    for key in list(stored.keys()):
        device_id = int(key)
        if device_id not in pending_device_ids:
            entry = stored.pop(key)
            removed.append({
                "device_id":   device_id,
                "full_name":   entry.get("full_name",   "?"),
                "employee_id": entry.get("employee_id", "?"),
            })
            logger.info(
                "state: auto-removed device=%s (%s %s) — no longer PENDING",
                device_id, entry.get("employee_id"), entry.get("full_name"),
            )

    if removed:
        _save_raw(data)

    return removed

