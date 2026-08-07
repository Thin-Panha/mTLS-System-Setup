"""
mpwt_admin/cmd_sites.py
Commands that manage the site registry:  site-add, site-remove, site-list.
Also shared helpers used by device commands to pick sites.
"""
from . import api
from .ui import (
    info, success, warn, error,
    bold, cyan,
    prompt, prompt_required, confirm, pick_number,
)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _fetch_registry() -> list[dict]:
    """
    Return the site registry sorted by creation order (ascending id).
    Each item: {"id": int, "hostname": str, "description": str}
    """
    raw = api.list_sites()
    if raw.get("status") != "ok":
        return []
    sites = raw.get("sites", [])
    # Fix problem 2: always sort by numeric id ascending (old → new)
    return sorted(sites, key=lambda s: int(s.get("id", 0)))


def _print_registry(sites: list[dict]) -> None:
    """Print the registry as a numbered list (1-based, sequential)."""
    print()
    print(bold("Registry sites:"))
    for i, site in enumerate(sites, 1):
        hostname = site.get("hostname", "")
        desc     = site.get("description", "")
        status   = "active" if site.get("active", True) else "inactive"
        print(f"  [{i}]  {hostname:<30}  {desc}  (active: {status})")
    print()


# ── Public pickers (used by device commands) ──────────────────────────────────

def pick_sites(exclude_hostnames: list[str] | None = None) -> list[str]:
    """
    Interactive multi-site picker.
    Optionally excludes already-assigned hostnames (shown as non-selectable).
    Returns the list of selected hostnames, or [] if user cancelled.
    """
    all_sites    = _fetch_registry()
    exclude_set  = set(exclude_hostnames or [])

    already      = [s for s in all_sites if s["hostname"] in exclude_set]
    available    = [s for s in all_sites if s["hostname"] not in exclude_set]

    print()

    if already:
        print(bold("Already assigned (not selectable):"))
        for s in already:
            print(f"  {cyan('✓')}  {s['hostname']}")
        print()

    if not available:
        warn("All registry sites are already assigned to this device.")
        return []

    print(bold("Available sites to add:"))
    for i, site in enumerate(available, 1):
        print(f"  {cyan(f'[{i}]')}  {site['hostname']:<30}  {site.get('description', '')}")
    print()
    print(f"  {cyan('[0]')}  Back to menu")
    print()

    while True:
        raw = prompt("Select sites (numbers separated by spaces or commas, or 0)").strip()

        if not raw or raw == "0":
            return []

        # Normalise separators
        parts = [p.strip() for p in raw.replace(",", " ").split() if p.strip()]
        if not parts:
            warn("No sites selected. Enter at least one number, or 0.")
            continue

        selected: list[str] = []
        valid = True
        for part in parts:
            if not part.isdigit():
                warn(f"  '{part}' is not a number.")
                valid = False
                break
            idx = int(part) - 1
            if idx < 0 or idx >= len(available):
                warn(f"  '{part}' is out of range (1–{len(available)}).")
                valid = False
                break
            selected.append(available[idx]["hostname"])

        if not valid:
            continue

        print()
        print(bold("Selected:"))
        for h in selected:
            print(f"  ✓  {h}")
        print()

        raw_confirm = prompt("Confirm? [Y/n]").strip()
        if raw_confirm == "" or raw_confirm.upper() == "Y":
    	    return selected
        return []
        # any other key → re-show the picker
        print()


# ── CLI commands ──────────────────────────────────────────────────────────────

def cmd_site_list(_args: list[str]) -> None:
    """site-list — list all registered sites."""
    sites = _fetch_registry()
    if not sites:
        warn("No sites in registry. Add one with: mpwt-admin site-add")
        return
    _print_registry(sites)


def cmd_site_add(args: list[str]) -> None:
    """site-add [--hostname HOST] [--desc DESC]"""
    hostname    = ""
    description = ""
    i = 0
    while i < len(args):
        if args[i] == "--hostname" and i + 1 < len(args):
            hostname = args[i + 1]; i += 2
        elif args[i] == "--desc" and i + 1 < len(args):
            description = args[i + 1]; i += 2
        else:
            error(f"Unknown flag: {args[i]}")

    # Fix problem 3: treat description like department — keep asking if empty
    if not hostname:
        hostname = prompt_required("Hostname (e.g. jira.mpwt.local)")
    if not description:
        description = prompt_required("Description")

    resp   = api.add_site(hostname, description)
    status = resp.get("status")
    if status == "ok":
        success(f"✅  Site registered: {hostname}  ({description})")
        info("Admins can now grant device access to this site with: mpwt-admin add-site")
    else:
        msg = resp.get("message", "Unknown error")
        error(f"Failed to register site: {msg}")


def cmd_site_remove(args: list[str]) -> None:
    """site-remove [--hostname HOST]"""
    hostname_flag = ""
    i = 0
    while i < len(args):
        if args[i] == "--hostname" and i + 1 < len(args):
            hostname_flag = args[i + 1]; i += 2
        else:
            error(f"Unknown flag: {args[i]}")

    sites = _fetch_registry()
    if not sites:
        warn("No sites in the registry.")
        return

    if hostname_flag:
        matches = [s for s in sites if s["hostname"] == hostname_flag]
        if not matches:
            error(f"Site '{hostname_flag}' not found in registry.")
        target = matches[0]
    else:
        _print_registry(sites)
        choice = pick_number(f"Select site to remove [1–{len(sites)}]", 1, len(sites))
        if choice is None:
            info("Cancelled.")
            return
        target = sites[choice - 1]

    hostname = target["hostname"]
    print()
    warn(f"Removing '{hostname}' from the registry.")
    warn("⚠  Any device currently granted access to this site may lose it.")
    print()
    if not confirm(f"Confirm removal of '{hostname}'?", default="N"):
        info("Cancelled — no changes made.")
        return

    resp   = api.remove_site(int(target["id"]))
    status = resp.get("status")
    if status == "ok":
        success(f"✅  '{hostname}' removed from registry.")
    else:
        msg = resp.get("message", "Unknown error")
        error(f"Failed to remove site: {msg}")
