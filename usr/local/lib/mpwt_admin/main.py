#!/usr/bin/env python3
"""
mpwt_admin/main.py
CLI dispatcher — maps sub-command strings to handler functions.
"""
import os
import sys

from mpwt_admin import audit
from mpwt_admin.api import KEYFETCH_HELPER


# ── Pre-flight checks ─────────────────────────────────────────────────────────

def _check_env() -> None:
    """
    Verify the caller can obtain the shared API key.

    We no longer require MPWT_API_KEY to be exported manually — the key
    lives in a group-readable file (see api.KEY_FILE). If that file can't
    be read AND no override env var is set, the user is almost certainly
    not a member of the mpwt-admin group.
    """
    from mpwt_admin.api import _api_key  # lazy import, avoids polluting startup

    if _api_key():
        return

    username = audit.resolve_username()
    in_group = audit.is_group_member(username)

    print("\033[0;31mCould not obtain the MPWT API key.\033[0m", file=sys.stderr)
    if not in_group:
        print(
            f"\033[0;31mUser '{username}' does not appear to be a member of the "
            f"'{audit.REQUIRED_GROUP}' group.\n"
            f"Ask an administrator to run:  usermod -aG {audit.REQUIRED_GROUP} {username}\n"
            f"(then log out and back in for the group membership to take effect)\033[0m",
            file=sys.stderr,
        )
    else:
        print(
            f"\033[0;31mUser '{username}' is in the '{audit.REQUIRED_GROUP}' group, "
            f"but the key could not be decrypted via {KEYFETCH_HELPER}.\n"
            f"Check that the helper exists, is owned root:{audit.REQUIRED_GROUP} with mode 2750 (setgid),\n"
            f"and that /etc/mpwt/creds/mpwt_api_key_cli.cred exists.\n"
            f"As a temporary override you can also: export MPWT_API_KEY=your_key\033[0m",
            file=sys.stderr,
        )
    sys.exit(1)


# ── Help text ─────────────────────────────────────────────────────────────────

HELP = """\
\033[1mmpwt-admin\033[0m — MPWT Zero Trust admin CLI

\033[1mDevice management:\033[0m

  \033[0;36madd-device\033[0m   [--id EMP_ID] [--name NAME] [--dept DEPT] [--email EMAIL] [--sites LIST]
               Create a new employee + device record and print the invite token.
               If the employee ID already exists, opens a management menu.
               Selecting no sites is allowed — they can be added later with add-site.

  \033[0;36minfo\033[0m         [--id EMP_ID]
               Show an employee's devices, cert status, and allowed sites.

  \033[0;36mlist\033[0m
               List all devices and their enrollment status.

  \033[0;36mnew-token\033[0m    [--id EMP_ID] [--device-id N]
               Generate a fresh invite token for a PENDING or REVOKED device.

  \033[0;36mrevoke\033[0m       [--id EMP_ID] [--device-id N]
  \033[0;36mcancel\033[0m       [--id EMP_ID] [--device-id N]
               Revoke an enrolled device (blocks access immediately),
               or cancel a pending device (voids the invite token).

\033[1mSite access per device:\033[0m

  \033[0;36madd-site\033[0m     [--id EMP_ID] [--device-id N]
               Grant a device access to one or more sites.

  \033[0;36mrevoke-site\033[0m  [--id EMP_ID] [--device-id N]
               Remove a device's access to one or more sites.

\033[1mSite registry:\033[0m

  \033[0;36msite-add\033[0m     [--hostname HOST] [--desc DESC]
               Register a new internal site.

  \033[0;36msite-remove\033[0m  [--hostname HOST]
               Remove a site from the registry.

  \033[0;36msite-list\033[0m    List all registered internal sites (sorted oldest → newest).

\033[1mDiagnostics:\033[0m

  \033[0;36mdebug\033[0m        Check API connectivity and print current configuration.

""".format(group=audit.REQUIRED_GROUP, helper=KEYFETCH_HELPER)

# ── Dispatch ──────────────────────────────────────────────────────────────────

def main() -> None:
    args    = sys.argv[1:]
    command = args[0] if args else "help"
    rest    = args[1:]

    if command in ("help", "--help", "-h"):
        print(HELP)
        return

    _check_env()

    # Every command past this point is authenticated and gets an audit entry.
    audit.log_action(command, rest, outcome="started")
    outcome = "ok"

    try:
        if command == "debug":
            if not _cmd_debug():
                outcome = "debug-checks-failed"
                sys.exit(1)

        # Lazy-import command modules (keeps startup fast, avoids circular issues)
        elif command == "add-device":
            from mpwt_admin.cmd_devices import cmd_add_device
            cmd_add_device(rest)

        elif command == "info":
            from mpwt_admin.cmd_devices import cmd_info
            cmd_info(rest)

        elif command == "list":
            from mpwt_admin.cmd_devices import cmd_list
            cmd_list(rest)

        elif command == "new-token":
            from mpwt_admin.cmd_devices import cmd_new_token
            cmd_new_token(rest)

        elif command in ("revoke", "cancel"):
            from mpwt_admin.cmd_devices import cmd_revoke
            cmd_revoke(rest)

        elif command == "add-site":
            from mpwt_admin.cmd_devices import cmd_add_site
            cmd_add_site(rest)

        elif command == "revoke-site":
            from mpwt_admin.cmd_devices import cmd_revoke_site
            cmd_revoke_site(rest)

        elif command == "site-add":
            from mpwt_admin.cmd_sites import cmd_site_add
            cmd_site_add(rest)

        elif command == "site-remove":
            from mpwt_admin.cmd_sites import cmd_site_remove
            cmd_site_remove(rest)

        elif command == "site-list":
            from mpwt_admin.cmd_sites import cmd_site_list
            cmd_site_list(rest)

        # Backward-compatible aliases so existing scripts don't break
        elif command == "registry-add":
            from mpwt_admin.cmd_sites import cmd_site_add
            cmd_site_add(rest)

        elif command == "registry-remove":
            from mpwt_admin.cmd_sites import cmd_site_remove
            cmd_site_remove(rest)

        elif command == "list-sites":
            from mpwt_admin.cmd_sites import cmd_site_list
            cmd_site_list(rest)

        else:
            outcome = "unknown-command"
            print(
                f"\033[0;31mUnknown command: {command}. "
                "Run 'mpwt-admin help' for usage.\033[0m",
                file=sys.stderr,
            )
            sys.exit(1)

    except SystemExit as e:
        outcome = "ok" if (e.code in (None, 0)) else f"exit-{e.code}"
        raise
    except Exception as e:
        outcome = f"error: {e}"
        raise
    finally:
        audit.log_action(command, rest, outcome=outcome)


def _cmd_debug() -> bool:
    """Check API reachability and print config (no sensitive values exposed).

    Returns True if all configuration checks passed, False otherwise.
    """
    from mpwt_admin import api
    from mpwt_admin.ui import success, warn, info, bold

    base = api._api_base()
    key  = api._api_key()
    username = audit.resolve_username()

    print()

    # ── Pass/fail validation summary ───────────────────────────────────────
    checks = {
        "ENROLLMENT_API_BASE": bool(base),
        "API key source":      os.path.exists(api.KEYFETCH_HELPER),
        "API key set":         bool(key),
        "Permission":          audit.is_group_member(username),
    }
    overall = all(checks.values())

    print(bold("── Validation ───────────────────────────────────────────"))
    print(f"  ENROLLMENT_API_BASE : {'TRUE' if checks['ENROLLMENT_API_BASE'] else 'FALSE'}")
    print(f"  API key source      : {'TRUE' if checks['API key source'] else 'FALSE'}")
    print(f"  Permission          : {'TRUE' if checks['Permission'] else 'FALSE'}")
    print()
    if overall:
        success("  DEBUG PASSED")
    else:
        warn("  DEBUG FAILED — see the FALSE line(s) above")
    print()

    print(bold("── Connectivity check ───────────────────────────────────"))

    # 1. Ping the site list (lightweight, read-only)
    resp = api.list_sites()
    if resp.get("status") == "ok":
        count = len(resp.get("sites", []))
        success(f"  ✓  API reachable — {count} site(s) in registry")
    else:
        warn(f"  ✗  API error: {resp.get('message', 'unknown')}")
        if "Cannot reach" in str(resp.get("message", "")):
            warn("     → Is the Flask API running?  "
                 "Check: systemctl status mpwt-api   or   ps aux | grep flask")

    # 2. Try listing devices
    resp2 = api.list_devices()
    if resp2.get("status") == "ok":
        count2 = len(resp2.get("devices", []))
        success(f"  ✓  /api/devices reachable — {count2} device(s) in DB")
    else:
        warn(f"  ✗  /api/devices error: {resp2.get('message', 'unknown')}")

    print()
    print(bold("── Hint for 'Database error' in Telegram bot ────────────"))
    info("  The bot's enrollment endpoint is separate from this admin CLI.")
    info("  'Database error' during CSR signing usually means one of:")
    info("   1. The Flask API process needs a restart (most common after deploys)")
    info("      →  sudo systemctl restart mpwt-api")
    info("   2. A DB migration is pending")
    info("      →  check Flask startup logs for SQLAlchemy errors")
    info("   3. The CA key/cert files moved or lost permissions")
    info("      →  check the path configured in the Flask app for CA_KEY / CA_CERT")
    print()

    return overall


if __name__ == "__main__":
    main()
