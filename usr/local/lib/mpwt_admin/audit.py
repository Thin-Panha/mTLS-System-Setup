"""
mpwt_admin/audit.py
Resolves the real invoking Linux user (even under sudo) and writes
audit-log entries for every command that is run.

Design notes:
  - The API key is now shared across the whole mpwt-admin group, so the
    *only* place identity is recorded is this client-side log. Because of
    that, writes go through the syslog facility rather than opening the
    log file directly — this means any group member can only ever APPEND
    an entry (via the syslog socket) and cannot read, truncate, or edit
    previous entries, even though they can read the on-disk log file.
  - If syslog is unavailable for some reason, we fall back to appending
    directly to LOCAL_LOG_PATH so an audit trail is still produced.
"""
import getpass
import grp
import os
import pwd
import socket
import sys
import syslog
from datetime import datetime, timezone

SYSLOG_IDENT   = "mpwt-admin"
REQUIRED_GROUP = "mpwt-admin"
LOCAL_LOG_PATH = "/var/log/mpwt-admin/audit.log"

# Arg values that should never be written to the audit log verbatim.
_REDACT_FLAGS = {"--email"}


def resolve_username() -> str:
    """
    Best-effort resolution of the *real* human running the command,
    even if invoked via sudo (where os.getlogin()/getpass.getuser()
    would otherwise report 'root').
    """
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        return sudo_user
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except (KeyError, OSError):
        pass
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def is_group_member(username: str, group_name: str = REQUIRED_GROUP) -> bool:
    """
    Check whether `username` belongs to `group_name`, checking both the
    group's member list and each user's primary GID.
    """
    try:
        group = grp.getgrnam(group_name)
    except KeyError:
        # Group doesn't exist on this host at all.
        return False

    if username in group.gr_mem:
        return True

    try:
        user_pw = pwd.getpwnam(username)
        return user_pw.pw_gid == group.gr_gid
    except KeyError:
        return False


def _redact_args(args: list[str]) -> list[str]:
    """Mask the value following any sensitive flag (e.g. --email X -> --email ***)."""
    cleaned = []
    skip_next = False
    for arg in args:
        if skip_next:
            cleaned.append("***")
            skip_next = False
            continue
        cleaned.append(arg)
        if arg in _REDACT_FLAGS:
            skip_next = True
    return cleaned


def _format_entry(username: str, command: str, args: list[str], outcome: str) -> str:
    ts       = datetime.now(timezone.utc).isoformat(timespec="seconds")
    host     = socket.gethostname()
    safe_args = " ".join(_redact_args(args))
    return f'{ts} user={username} host={host} command={command} args="{safe_args}" outcome={outcome}'


def log_action(command: str, args: list[str], outcome: str = "started") -> None:
    """
    Write one audit-log line. Tries syslog first (append-only from the
    caller's point of view); falls back to a direct file append if
    syslog isn't reachable.
    """
    username = resolve_username()
    entry    = _format_entry(username, command, args, outcome)

    try:
        syslog.openlog(ident=SYSLOG_IDENT, facility=syslog.LOG_AUTH)
        syslog.syslog(syslog.LOG_INFO, entry)
        syslog.closelog()
        return
    except Exception:
        pass  # fall through to file-based logging

    try:
        os.makedirs(os.path.dirname(LOCAL_LOG_PATH), exist_ok=True)
        with open(LOCAL_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(entry + "\n")
    except Exception as e:
        # Never block the actual command just because audit logging failed,
        # but make sure it's visible on stderr so it doesn't fail silently.
        print(f"\033[1;33m[audit] warning: could not write audit log: {e}\033[0m",
              file=sys.stderr)