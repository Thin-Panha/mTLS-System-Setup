"""
MarkdownV2 escaping helpers.
"""

_MDV2_RESERVED = r"\_*[]()~`>#+-=|{}.!"


def esc(text: str) -> str:
    """Escape all MarkdownV2 reserved characters in plain text."""
    for ch in _MDV2_RESERVED:
        text = text.replace(ch, f"\\{ch}")
    return text


def esc_code(text: str) -> str:
    """Escape backticks only — for inline code spans."""
    return text.replace("`", "\\`")
