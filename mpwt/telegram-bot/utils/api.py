"""
HTTP wrapper for the MPWT enrollment backend.

fetch_pending_devices() now returns devices in TWO categories:
  1. cert_status == 'PENDING'  — new device awaiting first enrollment
  2. cert_status == 'REVOKED' AND token_status == 'UNUSED'
                               — revoked device with a fresh re-enrollment token

Both categories have a valid, unused enroll_token and need the same
admin workflow: send guideline → receive CSR → issue certificate.

The 'reenroll' field is added by this function (not from server) so
handlers can show a label like "(re-enroll)" in the menu.
"""

import logging
import requests
from config.settings import settings

logger = logging.getLogger(__name__)


def _headers() -> dict:
    return {"X-API-Key": settings.API_KEY}


def api_call(method: str, path: str, **kwargs) -> requests.Response:
    url = f"{settings.API_BASE}{path}"
    existing_headers = kwargs.pop("headers", {})
    headers = {**_headers(), **existing_headers}
    return getattr(requests, method)(
        url,
        timeout=30,
        verify=settings.CA_CERT,
        headers=headers,
        **kwargs,
    )


def fetch_pending_devices() -> list[dict]:
    """
    Fetch all devices that need admin action:
      - PENDING  (cert_status=PENDING, any token_status)
      - RE-ENROLL (cert_status=REVOKED, token_status=UNUSED)

    Adds a boolean field 'reenroll' = True for the second category
    so the UI can label them differently.

    Returns empty list on error (caller handles messaging).
    Raises requests.RequestException on network error.
    """
    resp = api_call("get", "/api/devices")

    if resp.status_code != 200:
        logger.error(
            "fetch_pending_devices: server returned %s — %s",
            resp.status_code, resp.text[:200],
        )
        return []

    devices = resp.json().get("devices", [])

    result = []
    for d in devices:
        cert   = d.get("cert_status",  "")
        token  = d.get("token_status", "")

        if cert == "PENDING":
            d["reenroll"] = False
            result.append(d)

        elif cert == "REVOKED" and token == "UNUSED":
            d["reenroll"] = True
            result.append(d)

    logger.debug(
        "fetch_pending_devices: %d total devices, %d actionable (%d re-enroll)",
        len(devices),
        len(result),
        sum(1 for d in result if d.get("reenroll")),
    )
    return result


def fetch_device_status(device_id: int) -> str | None:
    """
    Return the cert_status of a single device, or None if not found/error.
    """
    try:
        resp = api_call("get", f"/api/devices/{device_id}")
    except requests.RequestException as e:
        logger.error("fetch_device_status device=%s error: %s", device_id, e)
        return None

    if resp.status_code == 404:
        return "NOT_FOUND"
    if resp.status_code != 200:
        logger.error("fetch_device_status device=%s: HTTP %s", device_id, resp.status_code)
        return None

    return resp.json().get("device", {}).get("cert_status")
