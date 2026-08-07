"""
routes/revoke.py — Certificate revocation
==========================================
Bug fixed
---------
The original route called  ca_service.revoke_cert(serial)  as if it were a
module-level function.  That function does not exist at module level.
The correct call is:

    CaService(current_app.config).revoke_certificate(serial)

This file fixes that and also:
  - Uses the same lazy g._ca_service pattern as enroll.py so the CA is only
    initialised once per Gunicorn worker, not once per request.
  - Updates cert_status → 'REVOKED' and sets revoked_at in the database.
  - Writes an audit_log row.
  - Returns clear JSON on every code path.
"""

import logging
from flask import Blueprint, request, jsonify, current_app, g
import database
from services.ca_service import CaService
import config

logger = logging.getLogger(__name__)

revoke_bp = Blueprint("revoke", __name__)


def _require_api_key():
    key = request.headers.get("X-API-Key", "")
    if key != config.MPWT_API_KEY:
        return jsonify(status="error", message="Unauthorized"), 401
    return None


def _get_ca() -> CaService:
    """Return a cached CaService instance for this worker (same pattern as enroll.py)."""
    if not hasattr(g, "_ca_service"):
        g._ca_service = CaService(current_app.config)
    return g._ca_service


@revoke_bp.route("/api/revoke/<int:device_id>", methods=["POST"])
def revoke_device(device_id: int):
    err = _require_api_key()
    if err:
        return err

    # ── Look up the device ────────────────────────────────────────────────────
    device = database.query_one(
        """
        SELECT d.id, d.employee_id, d.cert_serial, d.cert_status,
               d.device_name, d.os_type
        FROM   devices d
        WHERE  d.id = %s
        """,
        (device_id,),
    )

    if not device:
        return jsonify(status="error", message="Device not found"), 404

    cert_serial = device.get("cert_serial")
    cert_status = device.get("cert_status", "")

    if cert_status == "REVOKED":
        return jsonify(
            status="ok",
            message=f"Device {device_id} is already revoked.",
        ), 200

    if cert_status != "ACTIVE" or not cert_serial:
        return jsonify(
            status="error",
            message=f"Device {device_id} has no active certificate to revoke "
                    f"(status={cert_status}).",
        ), 400

    # ── Revoke with the CA ────────────────────────────────────────────────────
    try:
        ca = _get_ca()
        ca.revoke_certificate(cert_serial)          # ← correct method name
    except RuntimeError as e:
        logger.error("CaService init failed for device=%s: %s", device_id, e)
        return jsonify(
            status="error",
            message=f"PKI configuration error: {e}",
        ), 500
    except Exception as e:
        logger.exception("CA revocation failed device=%s serial=%s: %s",
                         device_id, cert_serial, e)
        return jsonify(
            status="error",
            message=f"CA revocation failed: {e}",
        ), 500

    # ── Mark revoked in the database ──────────────────────────────────────────
    try:
        database.execute_db(
            """
            UPDATE devices
            SET cert_status = 'REVOKED',
                revoked_at  = NOW(),
                updated_at  = NOW()
            WHERE id = %s
            """,
            (device_id,),
        )

        database.execute_db(
            """
            INSERT INTO audit_log
              (event, employee_id, device_id, detail, ip_address)
            VALUES
              ('CERT_REVOKED', %s, %s, %s, %s)
            """,
            (
                device["employee_id"],
                device_id,
                f"serial={cert_serial} device_name={device.get('device_name') or ''}",
                request.remote_addr,
            ),
        )
    except Exception as e:
        logger.exception("DB error after revocation device=%s: %s", device_id, e)
        return jsonify(
            status="error",
            message="Certificate was revoked in PKI but database update failed. "
                    "Contact IT admin.",
        ), 500

    logger.info(
        "Certificate revoked: device_id=%s employee_id=%s serial=%s",
        device_id, device["employee_id"], cert_serial,
    )

    return jsonify(
        status="ok",
        message=f"Certificate {cert_serial} revoked for device {device_id}.",
        device_id=device_id,
        serial=cert_serial,
    ), 200

