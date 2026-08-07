"""
mpwt_admin/ui.py
Terminal colour output and shared input helpers.
"""
import sys

# ANSI colour codes
RED    = "\033[0;31m"
GREEN  = "\033[0;32m"
YELLOW = "\033[1;33m"
CYAN   = "\033[0;36m"
BOLD   = "\033[1m"
NC     = "\033[0m"          # reset


def info(msg: str)    -> None: print(f"{CYAN}{msg}{NC}")
def success(msg: str) -> None: print(f"{GREEN}{msg}{NC}")
def warn(msg: str)    -> None: print(f"{YELLOW}{msg}{NC}")
def error(msg: str, exit_code: int = 1) -> None:
    print(f"{RED}{msg}{NC}", file=sys.stderr)
    sys.exit(exit_code)

def bold(text: str) -> str:
    return f"{BOLD}{text}{NC}"

def cyan(text: str) -> str:
    return f"{CYAN}{text}{NC}"

def red(text: str) -> str:
    return f"{RED}{text}{NC}"


# ── Generic prompt helpers ────────────────────────────────────────────────────

def prompt(label: str, default: str = "") -> str:
    """Display a bold prompt and return stripped input."""
    try:
        value = input(f"{BOLD}{label}{NC}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    return value or default


def prompt_required(label: str) -> str:
    """Keep asking until the user enters a non-empty value."""
    while True:
        value = prompt(label)
        if value:
            return value
        warn(f"{label} cannot be empty.")


def confirm(question: str, default: str = "N") -> bool:
    """
    Ask a yes/no question.
    Returns True for Y/y, False for N/n or empty (default).
    Typing '0' is treated as 'back/cancel' → returns False.
    """
    hint = "[Y/n/0]" if default.upper() == "Y" else "[y/N/0]"
    try:
        answer = input(f"{RED}{question}{NC} {hint} (0 = back): ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    if answer == "0":
        return False
    if answer == "":
        answer = default
    return answer.upper() == "Y"


def pick_number(prompt_text: str, lo: int, hi: int) -> int | None:
    """
    Ask for a single integer in [lo, hi].
    Returns None if the user enters 0 (back).
    """
    while True:
        raw = prompt(prompt_text)
        if raw == "0":
            return None
        if raw.isdigit():
            n = int(raw)
            if lo <= n <= hi:
                return n
        warn(f"Enter a number between {lo} and {hi}, or 0 to go back.")


def separator() -> None:
    print(f"{BOLD}{'━' * 63}{NC}")
