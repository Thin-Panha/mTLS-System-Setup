"""
Time formatting helpers.
"""

from datetime import datetime, timezone


def fmt_countdown(iso: str) -> str:
    """
    Returns countdown string from ISO timestamp.
    Examples:
        "47h 12m"
        "⚠️ 5h 44m left"  (under 6 hours)
        "⚠️ Expired"
        "?"
    """
    try:
        if iso.endswith("Z"):
            iso = iso[:-1] + "+00:00"
        expires = datetime.fromisoformat(iso)
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        diff          = expires - datetime.now(timezone.utc)
        total_seconds = int(diff.total_seconds())
        if total_seconds <= 0:
            return "⚠️ Expired"
        hours   = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        label   = f"{hours}h {minutes}m"
        if hours < 6:
            return f"⚠️ {label} left"
        return label
    except Exception:
        return "?"


def fmt_short_dt(iso: str) -> str:
    """
    Returns 'YYYY-MM-DD HH:MM' from ISO string, or '?'.
    Used for created_at / sent_at display.
    """
    try:
        return iso[:16].replace("T", " ")
    except Exception:
        return "?"
