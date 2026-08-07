"""
mpwt_admin/cmd_devices.py
Commands that manage devices and employees:
  add-device, info, list, new-token, revoke/cancel, add-site, revoke-site
"""
from . import api
from .ui import (
    info, success, warn, error,
    bold, cyan, red,
    prompt, prompt_required, confirm, pick_number,
    separator,
)
from .cmd_sites import pick_sites

from datetime import datetime
from zoneinfo import ZoneInfo

LOCAL_TZ = ZoneInfo("Asia/Phnom_Penh")

# ── Formatting helpers ────────────────────────────────────────────────────────

def _device_name(dev: dict) -> str:
    name = dev.get("device_name") or ""
    return name if name else "(pending enrollment)"


def _field(val) -> str:
    """Return '—' for falsy/null values."""
    if val is None or val == "" or str(val).lower() == "null":
        return "—"
    return str(val)


def _print_device(dev: dict, number: int) -> None:
    sites     = dev.get("sites") or []
    site_list = [
        (s["hostname"] if isinstance(s, dict) else s)
        for s in sites
    ]
    print(f"[Device {number}]")
    print(f"  Device ID:   {dev.get('id', '?')}")
    print(f"  Device name: {_device_name(dev)}")
    print(f"  OS:          {_field(dev.get('os_type'))}")
    print(f"  Status:      {_field(dev.get('cert_status'))}")
    print(f"  Cert serial: {_field(dev.get('cert_serial'))}")
    print(f"  Enrolled at: {_field(dev.get('enrolled_at'))}")
    print("  Allowed sites:")
    if site_list:
        for h in site_list:
            print(f"    - {h}")
    else:
        print("    (none)")
    print()


def _print_employee_header(raw: dict) -> None:
    emp        = raw.get("employee", {})
    devices    = raw.get("devices", [])
    separator()
    print(f"Employee ID '{cyan(emp.get('employee_id', '?'))}' already exists.")
    print(f"Name:       {emp.get('full_name', '?')}")
    print(f"Department: {emp.get('department', '?')}")
    print(f"Devices:    {len(devices)}")
    separator()
    print()
    print("Existing device(s):")
    print()
    for i, dev in enumerate(devices, 1):
        _print_device(dev, i)


def _format_expires(expires: str) -> str:
    """Convert an ISO timestamp (any offset) to local +07 display, matching the DB."""
    if not expires:
        return "—"
    try:
        dt = datetime.fromisoformat(expires)
        return dt.astimezone(LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S %z")
    except ValueError:
        return expires  # fallback: show raw value if parsing fails


def _print_token(token: str, expires: str) -> None:
    print()
    print(bold("━━━ INVITE TOKEN ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
    print(f"\033[1;33m{token}\033[0m")
    print(f"{bold('Expires:')} {_format_expires(expires)}")
    print(bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
    print()

# ── Device resolution helper ──────────────────────────────────────────────────

def _resolve_device(employee_id: str) -> int | None:
    """
    If the employee has exactly one device, return its id.
    If multiple, present a picker.
    Returns None on failure or cancel.
    """
    raw    = api.get_employee(employee_id)
    status = raw.get("status")
    if status != "ok":
        warn(f"Employee '{employee_id}': {raw.get('message', 'not found')}")
        return None

    devices = raw.get("devices", [])
    if not devices:
        warn(f"Employee '{employee_id}' has no devices.")
        return None

    if len(devices) == 1:
        return int(devices[0]["id"])

    # Multiple devices — let user pick
    print()
    print(bold(f"Employee '{employee_id}' has multiple devices:"))
    for i, dev in enumerate(devices, 1):
        dev_id   = dev.get("id", "?")
        name     = _device_name(dev)
        status_s = dev.get("cert_status", "UNKNOWN")
        print(f"  {cyan(f'[{i}]')}  Device ID: {str(dev_id):<5}  "
              f"Name: {name:<25}  Status: {status_s}")
    print()

    choice = pick_number(f"Select device [1–{len(devices)}]", 1, len(devices))
    if choice is None:
        return None
    return int(devices[choice - 1]["id"])


# ── Core actions (reused by multiple commands) ────────────────────────────────

def _do_new_token(device_id: int) -> None:
    dev_raw = api.get_device(device_id)
    if dev_raw.get("status") != "ok":
        warn(f"Could not fetch device {device_id}: "
             f"{dev_raw.get('message', 'unknown error')}")
        return

    dev         = dev_raw.get("device", {})
    cert_status = dev.get("cert_status", "UNKNOWN")
    cert_serial = _field(dev.get("cert_serial"))
    name        = _device_name(dev)

    if cert_status == "ACTIVE":
        print()
        warn(f"Device {device_id} ({name}) is ACTIVE — "
             f"certificate {cert_serial} already issued.")
        print(f"  Options:")
        print(f"  {cyan('[1]')}  Revoke this device and create a new one  "
              "(lost / compromised device)")
        print(f"  {cyan('[0]')}  Back to menu")
        print()
        choice = pick_number("Choice [0 or 1]", 1, 1)
        if choice == 1:
            _do_revoke(device_id)
        return

    if cert_status == "REVOKED":
        warn(f"Device {device_id} is REVOKED. "
             "A new token will allow re-enrollment.")
        if not confirm("Generate token anyway?", default="N"):
            info("No action taken.")
            return

    info(f"Generating new token for device {device_id}…")
    resp = api.new_token(device_id)
    if resp.get("status") != "ok":
        warn(f"Failed to generate token: "
             f"{resp.get('message', 'unknown error')}")
        return

    _print_token(resp.get("invite_token", ""), resp.get("token_expires", ""))
    success(f"New invite token generated for device {device_id}.")


def _do_revoke(device_id: int) -> None:
    dev_raw = api.get_device(device_id)
    if dev_raw.get("status") != "ok":
        warn(f"Could not fetch device {device_id}: "
             f"{dev_raw.get('message', 'unknown error')}")
        return

    dev         = dev_raw.get("device", {})
    emp_id      = dev.get("employee_id", "?")
    name        = _device_name(dev)
    cert_serial = _field(dev.get("cert_serial"))
    cert_status = dev.get("cert_status", "UNKNOWN")

    print()
    print(bold("Device details:"))
    print(f"  Employee:  {emp_id}")
    print(f"  Device ID: {device_id}")
    print(f"  Device:    {name}")
    print(f"  Serial:    {cert_serial}")
    print(f"  Status:    {cert_status}")
    print()

    if cert_status == "PENDING":
        warn("This device has not enrolled yet — cancelling will void the invite token.")
        print()
        if not confirm("Cancel this pending device?", default="N"):
            info("Cancelled — no changes made.")
            return
        resp = api.cancel_device(device_id)
        if resp.get("status") == "ok":
            success(f"✅  Pending device {device_id} cancelled.")
            info("The invite token is now void.")
        else:
            warn(f"Cancel failed: {resp.get('message', 'unknown error')}")
        return

    if cert_status == "REVOKED":
        warn(f"Device {device_id} is already REVOKED. No action needed.")
        return

    if not confirm(f"Revoke certificate {cert_serial} for device {device_id}?",
                   default="N"):
        info("Cancelled — no changes made.")
        return

    warn(f"Revoking certificate for device {device_id}…")
    resp = api.revoke_device(device_id)
    if resp.get("status") == "ok":
        success(f"✅  Certificate {cert_serial} revoked.")
        msg = resp.get("message", "")
        if msg:
            print(msg)
    else:
        warn(f"Revocation failed: {resp.get('message', 'unknown error')}")


def _do_add_sites(device_id: int, current_hostnames: list[str]) -> None:
    selected = pick_sites(exclude_hostnames=current_hostnames)
    if not selected:
        warn("No sites selected.")
        return
    for hostname in selected:
        resp   = api.add_device_site(device_id, hostname)
        status = resp.get("status")
        if status == "ok":
            success(f"  ✓  {hostname} access granted to device {device_id}")
        else:
            warn(f"  ✗  {hostname}: {resp.get('message', 'failed')}")


def _do_revoke_site(device_id: int) -> None:
    raw    = api.get_device_sites(device_id)
    status = raw.get("status")
    if status != "ok":
        warn(f"Could not fetch sites for device {device_id}: "
             f"{raw.get('message', 'unknown error')}")
        return

    sites = raw.get("sites", [])
    if not sites:
        warn(f"Device {device_id} has no assigned sites.")
        return

    print()
    print(bold(f"Currently assigned sites for device {device_id}:"))
    for i, site in enumerate(sites, 1):
        print(f"  {cyan(f'[{i}]')}  {site.get('hostname', '?')}")
    print()
    print(f"  {cyan('[0]')}  Back to menu")
    print()

    while True:
        raw_sel = prompt(
            "Select site(s) to revoke (numbers, e.g. 1 2, or 0)"
        ).strip()

        if not raw_sel or raw_sel == "0":
            return

        parts = [p.strip() for p in raw_sel.replace(",", " ").split() if p.strip()]
        if not parts:
            warn("No selection. Enter number(s) or 0.")
            continue

        to_remove: list[dict] = []
        valid = True
        for part in parts:
            if not part.isdigit():
                warn(f"'{part}' is not a number.")
                valid = False
                break
            idx = int(part) - 1
            if idx < 0 or idx >= len(sites):
                warn(f"'{part}' is out of range (1–{len(sites)}).")
                valid = False
                break
            to_remove.append(sites[idx])

        if not valid:
            continue

        print()
        print(bold("Will revoke access to:"))
        for s in to_remove:
            print(f"  ✗  {s.get('hostname', '?')}")
        print()

        if not confirm("Confirm revoke?", default="N"):
            info("Cancelled.")
            return

        for site in to_remove:
            resp   = api.remove_device_site(device_id, int(site["id"]))
            status = resp.get("status")
            if status == "ok":
                success(f"  ✓  {site['hostname']} revoked from device {device_id}")
            else:
                warn(f"  ✗  {site['hostname']}: {resp.get('message', 'failed')}")
        break


def _do_create_device(
    employee_id: str,
    full_name:   str,
    department:  str,
    email:       str | None,
    sites:       list[str],
) -> None:
    """
    Call the API to create a device record.
    Fix problem 1: if sites is empty, create the device anyway (no sites yet)
    and display the invite token.
    """
    info("\nCreating device record…")
    resp   = api.create_device(employee_id, full_name, department, email, sites)
    status = resp.get("status")

    if status != "ok":
        msg = resp.get("message", "Unknown error")
        warn(f"Failed to create device: {msg}")
        return

    token     = resp.get("invite_token", "")
    expires   = resp.get("token_expires", "")
    device_id = resp.get("device_id", "?")

    print()
    success(f"✅  Device created  (ID: {device_id})")
    print(f"{bold('Employee:')}     {full_name} ({employee_id})")
    if sites:
        print(f"{bold('Sites:')}        {', '.join(sites)}")
    else:
        print(f"{bold('Sites:')}        (none assigned yet — use 'mpwt-admin add-site' later)")
    print(f"{bold('Device name:')}  will be captured automatically when employee enrolls")
    _print_token(token, expires)


# ── Existing-employee sub-menu ────────────────────────────────────────────────

def _existing_employee_menu(employee_id: str, raw: dict) -> None:
    emp       = raw.get("employee", {})
    full_name = emp.get("full_name", "?")
    dept      = emp.get("department", "?")

    while True:
        print("What would you like to do?")
        print("  [1] View / refresh info only")
        print("  [2] Add site access to a device")
        print("  [3] Revoke site access from a device")
        print("  [4] Generate a new invite token for a device")
        print("  [5] Revoke / cancel a device")
        print("  [6] Create another device for this employee")
        print("  [0] Cancel / exit")
        print()

        choice = prompt("Choice").strip()

        if choice == "0":
            info("Cancelled.")
            return

        elif choice == "1":
            raw = api.get_employee(employee_id)
            _print_employee_header(raw)

        elif choice == "2":
            dev_id = _resolve_device(employee_id)
            if dev_id is not None:
                dev_raw          = api.get_device(dev_id)
                current_sites    = dev_raw.get("device", {}).get("sites") or []
                current_hostnames = [
                    (s["hostname"] if isinstance(s, dict) else s)
                    for s in current_sites
                ]
                _do_add_sites(dev_id, current_hostnames)
                raw = api.get_employee(employee_id)

        elif choice == "3":
            dev_id = _resolve_device(employee_id)
            if dev_id is not None:
                _do_revoke_site(dev_id)
                raw = api.get_employee(employee_id)

        elif choice == "4":
            dev_id = _resolve_device(employee_id)
            if dev_id is not None:
                _do_new_token(dev_id)

        elif choice == "5":
            dev_id = _resolve_device(employee_id)
            if dev_id is not None:
                _do_revoke(dev_id)
                raw = api.get_employee(employee_id)

        elif choice == "6":
            print()
            # Fix problem 1: allow creating device with no sites
            sites = pick_sites()
            _do_create_device(employee_id, full_name, dept, None, sites)
            raw = api.get_employee(employee_id)
#            _print_employee_header(raw)

        else:
            warn("Invalid choice — enter 0–6.")

        print()


# ── CLI commands ──────────────────────────────────────────────────────────────

def cmd_add_device(args: list[str]) -> None:
    """add-device [--id EMP_ID] [--name NAME] [--dept DEPT] [--email EMAIL] [--sites LIST]"""
    employee_id = ""
    full_name   = ""
    department  = ""
    email       = ""
    sites_flag  = ""

    i = 0
    while i < len(args):
        if args[i] == "--id"    and i + 1 < len(args): employee_id = args[i+1]; i += 2
        elif args[i] == "--name"  and i + 1 < len(args): full_name   = args[i+1]; i += 2
        elif args[i] == "--dept"  and i + 1 < len(args): department  = args[i+1]; i += 2
        elif args[i] == "--email" and i + 1 < len(args): email       = args[i+1]; i += 2
        elif args[i] == "--sites" and i + 1 < len(args): sites_flag  = args[i+1]; i += 2
        else: error(f"Unknown flag: {args[i]}")

    if not employee_id:
        employee_id = prompt_required("Employee ID (e.g. EMP001)")
    employee_id = employee_id.strip()

    # Check if employee already exists
    existing = api.get_employee(employee_id)
    if existing.get("status") == "ok":
        _print_employee_header(existing)
        _existing_employee_menu(employee_id, existing)
        return

    # New employee — collect details
    if not full_name:
        full_name = prompt_required("Full name")
    if not department:
        department = prompt_required("Department")
    if not email:
        email = prompt("Email (optional — press Enter to skip)")

    # Fix problem 1: allow proceeding with no sites
    sites: list[str] = []
    if sites_flag:
        sites = [s.strip() for s in sites_flag.split(",") if s.strip()]
    else:
        sites = pick_sites()
        # No longer abort if sites is empty — just proceed without sites

    _do_create_device(employee_id, full_name, department, email or None, sites)


def cmd_info(args: list[str]) -> None:
    """info [--id EMP_ID]"""
    employee_id = ""
    i = 0
    while i < len(args):
        if args[i] == "--id" and i + 1 < len(args):
            employee_id = args[i+1]; i += 2
        else:
            error(f"Unknown flag: {args[i]}")

    if not employee_id:
        employee_id = prompt_required("Employee ID")
    employee_id = employee_id.strip()

    raw    = api.get_employee(employee_id)
    status = raw.get("status")
    if status != "ok":
        error(f"Employee '{employee_id}': {raw.get('message', 'not found')}")

    emp     = raw.get("employee", {})
    devices = raw.get("devices", [])

    print()
    print(f"{bold('Employee:')}   {emp.get('full_name', '?')} ({employee_id})")
    print(f"{bold('Department:')} {emp.get('department', '?')}")
    print()
    for i, dev in enumerate(devices, 1):
        _print_device(dev, i)


def cmd_list(args: list[str]) -> None:
    """list — list all devices."""
    info("Fetching all devices…")
    print()
    raw     = api.list_devices()
    devices = raw.get("devices", [])
    if not devices:
        warn("No devices found.")
        return
    for dev in devices:
        print(f"  {bold('ID:')}      {dev.get('id', '?')}")
        print(f"  Employee: {dev.get('employee_id', '?')}")
        print(f"  Device:   {_device_name(dev)}")
        print(f"  OS:       {_field(dev.get('os_type'))}")
        print(f"  Status:   {_field(dev.get('cert_status'))}")
        print(f"  Serial:   {_field(dev.get('cert_serial'))}")
        print(f"  Enrolled: {_field(dev.get('enrolled_at'))}")
        print()


def cmd_new_token(args: list[str]) -> None:
    """new-token [--id EMP_ID] [--device-id N]"""
    employee_id    = ""
    device_id_flag = ""
    i = 0
    while i < len(args):
        if args[i] == "--id"        and i + 1 < len(args): employee_id    = args[i+1]; i += 2
        elif args[i] == "--device-id" and i + 1 < len(args): device_id_flag = args[i+1]; i += 2
        else: error(f"Unknown flag: {args[i]}")

    if device_id_flag:
        dev_id = int(device_id_flag)
    else:
        if not employee_id:
            employee_id = prompt_required("Employee ID (e.g. EMP001)")
        employee_id = employee_id.strip()
        dev_id = _resolve_device(employee_id)
        if dev_id is None:
            return

    _do_new_token(dev_id)


def cmd_revoke(args: list[str]) -> None:
    """revoke/cancel [--id EMP_ID] [--device-id N]"""
    employee_id    = ""
    device_id_flag = ""
    i = 0
    while i < len(args):
        if args[i] == "--id"        and i + 1 < len(args): employee_id    = args[i+1]; i += 2
        elif args[i] == "--device-id" and i + 1 < len(args): device_id_flag = args[i+1]; i += 2
        else: error(f"Unknown flag: {args[i]}")

    if device_id_flag:
        dev_id = int(device_id_flag)
    else:
        if not employee_id:
            employee_id = prompt_required("Employee ID (e.g. EMP001)")
        employee_id = employee_id.strip()
        dev_id = _resolve_device(employee_id)
        if dev_id is None:
            return

    _do_revoke(dev_id)


def cmd_add_site(args: list[str]) -> None:
    """add-site [--id EMP_ID] [--device-id N]"""
    employee_id    = ""
    device_id_flag = ""
    i = 0
    while i < len(args):
        if args[i] == "--id"        and i + 1 < len(args): employee_id    = args[i+1]; i += 2
        elif args[i] == "--device-id" and i + 1 < len(args): device_id_flag = args[i+1]; i += 2
        else: error(f"Unknown flag: {args[i]}")

    if device_id_flag:
        dev_id = int(device_id_flag)
    else:
        if not employee_id:
            employee_id = prompt_required("Employee ID (e.g. EMP001)")
        employee_id = employee_id.strip()
        dev_id = _resolve_device(employee_id)
        if dev_id is None:
            return

    dev_raw           = api.get_device(dev_id)
    current_sites     = dev_raw.get("device", {}).get("sites") or []
    current_hostnames = [
        (s["hostname"] if isinstance(s, dict) else s)
        for s in current_sites
    ]
    _do_add_sites(dev_id, current_hostnames)


def cmd_revoke_site(args: list[str]) -> None:
    """revoke-site [--id EMP_ID] [--device-id N]"""
    employee_id    = ""
    device_id_flag = ""
    i = 0
    while i < len(args):
        if args[i] == "--id"        and i + 1 < len(args): employee_id    = args[i+1]; i += 2
        elif args[i] == "--device-id" and i + 1 < len(args): device_id_flag = args[i+1]; i += 2
        else: error(f"Unknown flag: {args[i]}")

    if device_id_flag:
        dev_id = int(device_id_flag)
    else:
        if not employee_id:
            employee_id = prompt_required("Employee ID (e.g. EMP001)")
        employee_id = employee_id.strip()
        dev_id = _resolve_device(employee_id)
        if dev_id is None:
            return

    _do_revoke_site(dev_id)
