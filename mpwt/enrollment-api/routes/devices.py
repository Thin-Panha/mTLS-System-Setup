"""
IT Admin device management
==========================
POST   /api/employees                           — create employee
GET    /api/employees                           — list employees
GET    /api/employees/<employee_id>             — get one employee + all their devices + sites
POST   /api/devices                             — create device + assign sites + generate token
GET    /api/devices                             — list all devices
GET    /api/devices/<device_id>                 — get one device
POST   /api/devices/<device_id>/sites           — assign a site
DELETE /api/devices/<device_id>/sites/<site_id> — unassign a site
GET    /api/devices/<device_id>/sites           — list assigned sites
POST   /api/devices/<device_id>/token           — (re-)generate invite token
DELETE /api/devices/<device_id>                 — cancel a PENDING device (voids token, deletes record)
"""
from flask import Blueprint, request, jsonify
import services.device_service as device_svc
import services.token_service  as token_svc
import config

devices_bp = Blueprint("devices", __name__)

def _require_api_key():
    key = request.headers.get("X-API-Key", "")
    if key != config.MPWT_API_KEY:
        return jsonify(status="error", message="Unauthorized"), 401
    return None

# ── Employees ──────────────────────────────────────────────────────────────────

@devices_bp.route("/api/employees", methods=["POST"])
def create_employee():
    err = _require_api_key()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    employee_id = (data.get("employee_id") or "").strip()
    full_name   = (data.get("full_name")   or "").strip()
    department  = (data.get("department")  or "").strip()
    email       = (data.get("email")       or "").strip() or None

    if not employee_id or not full_name or not department:
        return jsonify(status="error",
                       message="employee_id, full_name, department required"), 400

    emp = device_svc.create_employee(employee_id, full_name, department, email)
    return jsonify(status="ok", employee=emp), 201


@devices_bp.route("/api/employees", methods=["GET"])
def list_employees():
    err = _require_api_key()
    if err:
        return err
    from database import query_all
    rows = query_all("SELECT * FROM employees ORDER BY created_at DESC")
    return jsonify(status="ok", employees=rows)


@devices_bp.route("/api/employees/<employee_id>", methods=["GET"])
def get_employee(employee_id):
    """
    Return the employee record + all their devices, each with assigned sites.
    Used by the admin CLI to:
      - detect whether an employee ID already exists (add-device)
      - show full info (info command, management menu)
      - resolve employee ID → device IDs (new-token, revoke, assign-site, remove-site)

    Response shape:
    {
      "status": "ok",
      "employee": { employee fields … },
      "devices": [
        {
          device fields …,
          "sites": [
            { "id": 1, "hostname": "dev.mpwt.local", "description": "…" },
            …
          ]
        },
        …
      ]
    }
    """
    err = _require_api_key()
    if err:
        return err

    emp = device_svc.get_employee(employee_id)
    if not emp:
        return jsonify(status="error", message="Employee not found"), 404

    devices = device_svc.list_devices(employee_id)
    for dev in devices:
        dev["sites"] = device_svc.get_device_sites(dev["id"])

    return jsonify(status="ok", employee=emp, devices=devices)


# ── Devices ────────────────────────────────────────────────────────────────────

@devices_bp.route("/api/devices", methods=["POST"])
def create_device():
    """
    Create employee (if needed), create device, assign sites, generate invite token.
    Body:
    {
      "employee_id": "EMP001",
      "full_name":   "John Doe",
      "department":  "IT",
      "email":       "john@mpwt.gov.kh",   // optional
      "sites":       ["dev.mpwt.local", "wazuh.mpwt.local"]
    }
    """
    err = _require_api_key()
    if err:
        return err

    data        = request.get_json(silent=True) or {}
    employee_id = (data.get("employee_id") or "").strip()
    full_name   = (data.get("full_name")   or "").strip()
    department  = (data.get("department")  or "").strip()
    email       = (data.get("email")       or "").strip() or None
    site_hosts  = data.get("sites", [])

    if not employee_id or not full_name or not department:
        return jsonify(status="error",
                       message="employee_id, full_name, department required"), 400

    # Upsert employee
    device_svc.create_employee(employee_id, full_name, department, email)

    # Create device
    device = device_svc.create_device(employee_id)
    device_id = device["id"]

    # Resolve + assign sites
    all_sites = {s["hostname"]: s["id"] for s in device_svc.list_sites()}
    bad_sites = [h for h in site_hosts if h not in all_sites]
    if bad_sites:
        return jsonify(status="error",
                       message=f"Unknown sites: {bad_sites}"), 400

    admin_id = request.headers.get("X-Admin-ID", "admin")
    for host in site_hosts:
        device_svc.assign_site(device_id, all_sites[host], granted_by=admin_id)

    # Generate invite token
    token_info = token_svc.create_invite_token(device_id, created_by=admin_id)

    device_svc.audit(
        event       = "DEVICE_CREATED",
        employee_id = employee_id,
        device_id   = device_id,
        detail      = f"sites={site_hosts}",
        ip_address  = request.remote_addr,
    )

    return jsonify(
        status       = "ok",
        device_id    = device_id,
        employee_id  = employee_id,
        sites        = site_hosts,
        invite_token = token_info["token"],
        token_expires= token_info["expires"],
        message      = (
            f"Send this token to {full_name}: {token_info['token']}\n"
            f"Expires: {token_info['expires']}"
        ),
    ), 201


@devices_bp.route("/api/devices", methods=["GET"])
def list_devices():
    err = _require_api_key()
    if err:
        return err
    employee_id = request.args.get("employee_id")
    rows = device_svc.list_devices(employee_id)

    # Compute per-employee device_number, matching CLI's [Device N] ordering.
    # list_devices() already returns rows ORDER BY created_at ASC, so we just
    # count per employee as we iterate — no sorting needed here.
    emp_counters = {}
    for row in rows:
        eid = row["employee_id"]
        emp_counters[eid] = emp_counters.get(eid, 0) + 1
        row["device_number"] = emp_counters[eid]

    return jsonify(status="ok", devices=rows)


@devices_bp.route("/api/devices/<int:device_id>", methods=["GET"])
def get_device(device_id):
    err = _require_api_key()
    if err:
        return err
    device = device_svc.get_device_by_id(device_id)
    if not device:
        return jsonify(status="error", message="Not found"), 404
    sites = device_svc.get_device_sites(device_id)
    device["sites"] = sites
    return jsonify(status="ok", device=device)


# ── Site assignment ────────────────────────────────────────────────────────────

@devices_bp.route("/api/devices/<int:device_id>/sites", methods=["GET"])
def get_device_sites(device_id):
    err = _require_api_key()
    if err:
        return err
    sites = device_svc.get_device_sites(device_id)
    return jsonify(status="ok", sites=sites)


@devices_bp.route("/api/devices/<int:device_id>/sites", methods=["POST"])
def assign_site(device_id):
    err = _require_api_key()
    if err:
        return err
    data     = request.get_json(silent=True) or {}
    hostname = (data.get("hostname") or "").strip()
    if not hostname:
        return jsonify(status="error", message="hostname required"), 400

    from database import query_one
    site = query_one("SELECT * FROM sites WHERE hostname = %s AND active = TRUE", (hostname,))
    if not site:
        return jsonify(status="error", message=f"Site not found: {hostname}"), 404

    admin_id = request.headers.get("X-Admin-ID", "admin")
    device_svc.assign_site(device_id, site["id"], granted_by=admin_id)

    device_svc.audit(
        event     = "SITE_ASSIGNED",
        device_id = device_id,
        detail    = f"hostname={hostname} granted_by={admin_id}",
        ip_address= request.remote_addr,
    )

    return jsonify(status="ok", message=f"{hostname} assigned to device {device_id}")


@devices_bp.route("/api/devices/<int:device_id>/sites/<int:site_id>",
                  methods=["DELETE"])
def unassign_site(device_id, site_id):
    err = _require_api_key()
    if err:
        return err

    from database import query_one
    site = query_one("SELECT hostname FROM sites WHERE id = %s", (site_id,))
    device_svc.unassign_site(device_id, site_id)

    admin_id = request.headers.get("X-Admin-ID", "admin")
    device_svc.audit(
        event     = "SITE_UNASSIGNED",
        device_id = device_id,
        detail    = f"site_id={site_id} hostname={site['hostname'] if site else '?'} by={admin_id}",
        ip_address= request.remote_addr,
    )

    return jsonify(status="ok",
                   message=f"Site {site_id} removed from device {device_id}")


# ── Cancel (delete) a PENDING device ──────────────────────────────────────────

@devices_bp.route("/api/devices/<int:device_id>", methods=["DELETE"])
def cancel_device(device_id):
    """
    Cancel a PENDING device — deletes the record and voids the invite token.
    Only allowed when cert_status = PENDING (no certificate has been issued).
    For ACTIVE devices, use POST /api/revoke/<device_id> instead.
    """
    err = _require_api_key()
    if err:
        return err

    device = device_svc.get_device_by_id(device_id)
    if not device:
        return jsonify(status="error", message="Device not found"), 404

    cert_status = device.get("cert_status", "")

    if cert_status == "ACTIVE":
        return jsonify(
            status="error",
            message=(
                f"Device {device_id} has an ACTIVE certificate. "
                "Use POST /api/revoke/{device_id} to revoke it first, "
                "then delete if needed."
            ),
        ), 409

    if cert_status == "REVOKED":
        return jsonify(
            status="error",
            message=(
                f"Device {device_id} is already REVOKED. "
                "Its certificate is no longer valid. "
                "Delete the record only after confirming no audit dependency."
            ),
        ), 409

    # PENDING — safe to delete outright
    employee_id = device.get("employee_id", "?")

    from database import execute_db
    execute_db("DELETE FROM devices WHERE id = %s", (device_id,))

    device_svc.audit(
        event       = "DEVICE_CANCELLED",
        employee_id = employee_id,
        device_id   = device_id,
        detail      = "PENDING device cancelled by admin — token voided, record deleted",
        ip_address  = None,
    )

    return jsonify(
        status    = "ok",
        message   = f"Pending device {device_id} cancelled and removed.",
        device_id = device_id,
    )


# ── Re-generate invite token ───────────────────────────────────────────────────

@devices_bp.route("/api/devices/<int:device_id>/token", methods=["POST"])
def regenerate_token(device_id):
    err = _require_api_key()
    if err:
        return err
    device = device_svc.get_device_by_id(device_id)
    if not device:
        return jsonify(status="error", message="Device not found"), 404

    admin_id   = request.headers.get("X-Admin-ID", "admin")
    token_info = token_svc.create_invite_token(device_id, created_by=admin_id)

    return jsonify(
        status        = "ok",
        invite_token  = token_info["token"],
        token_expires = token_info["expires"],
    )
