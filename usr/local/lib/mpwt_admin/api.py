"""
mpwt_admin/api.py
Low-level HTTP client that talks to the enrollment REST API.

ENV vars are read at call-time (not import-time) so that the script works
correctly even when MPWT_API_KEY / ENROLLMENT_API_BASE are exported after
the module is first imported.
"""
import os
import json
import urllib.request
import urllib.error
from typing import Any
import subprocess

KEYFETCH_HELPER = "/usr/local/lib/mpwt_admin/mpwt-admin-keyfetch"


def _api_base() -> str:
    return os.environ.get("ENROLLMENT_API_BASE", "http://127.0.0.1:5000").rstrip("/")


def _api_key() -> str:
    """
    Resolve the shared API key by invoking the setgid keyfetch helper,
    which runs `systemd-creds decrypt` on the CLI's protected credential.

    Falls back to MPWT_API_KEY env var if the helper isn't present/working
    (useful during migration, or on a dev box without systemd-creds set up).
    """
    try:
        result = subprocess.run(
            [KEYFETCH_HELPER],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            key = result.stdout.strip()
            if key:
                return key
        # Helper ran but failed (not in group, cred missing, etc.) — surface
        # nothing here; _check_env() in main.py handles the error messaging.
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        pass

    return os.environ.get("MPWT_API_KEY", "")


def _request(method: str, path: str, body: dict | None = None) -> dict:
    """Send an authenticated API request; return parsed JSON."""
    url  = f"{_api_base()}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {
        "X-API-Key":    _api_key(),
        "Content-Type": "application/json",
    }
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read().decode("utf-8"))
            # Attach HTTP status so callers can inspect it
            payload.setdefault("http_status", e.code)
            return payload
        except Exception:
            return {"status": "error", "message": f"HTTP {e.code}", "http_status": e.code}
    except urllib.error.URLError as e:
        return {"status": "error", "message": f"Cannot reach API: {e.reason}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def get(path: str) -> dict:
    return _request("GET", path)

def post(path: str, body: dict | None = None) -> dict:
    return _request("POST", path, body)

def delete(path: str, body: dict | None = None) -> dict:
    return _request("DELETE", path, body)


# ── Employee helpers ──────────────────────────────────────────────────────────

def get_employee(employee_id: str) -> dict:
    return get(f"/api/employees/{employee_id}")

def create_device(
    employee_id: str,
    full_name:   str,
    department:  str,
    email:       str | None,
    sites:       list[str],
) -> dict:
    body: dict[str, Any] = {
        "employee_id": employee_id,
        "full_name":   full_name,
        "department":  department,
        "sites":       sites,
    }
    # Only include email key when a value was actually provided.
    # Sending "email": null can cause NOT-NULL constraint errors on some
    # DB schemas — omitting the key lets the server apply its own default.
    if email:
        body["email"] = email
    return post("/api/devices", body)


# ── Device helpers ────────────────────────────────────────────────────────────

def get_device(device_id: int) -> dict:
    return get(f"/api/devices/{device_id}")

def list_devices() -> dict:
    return get("/api/devices")

def new_token(device_id: int) -> dict:
    return post(f"/api/devices/{device_id}/token")

def revoke_device(device_id: int) -> dict:
    return post(f"/api/revoke/{device_id}")

def cancel_device(device_id: int) -> dict:
    return delete(f"/api/devices/{device_id}")


# ── Device-site helpers ───────────────────────────────────────────────────────

def get_device_sites(device_id: int) -> dict:
    return get(f"/api/devices/{device_id}/sites")

def add_device_site(device_id: int, hostname: str) -> dict:
    return post(f"/api/devices/{device_id}/sites", {"hostname": hostname})

def remove_device_site(device_id: int, site_id: int) -> dict:
    return delete(f"/api/devices/{device_id}/sites/{site_id}")


# ── Site-registry helpers ─────────────────────────────────────────────────────

def list_sites() -> dict:
    return get("/api/sites")

def add_site(hostname: str, description: str) -> dict:
    return post("/api/sites", {"hostname": hostname, "description": description})

def remove_site(site_id: int) -> dict:
    return delete(f"/api/sites/{site_id}")
