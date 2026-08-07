"""
routes/enroll.py — CSR-based enrollment (Server-Verified Policy Binding)
=========================================================================
"""

import logging
import os
import re
from flask import Blueprint, request, jsonify, current_app, g
import database
from services.ca_service    import CaService
from services.policy_service import (
    generate_config_file,
    get_run_command,
    verify_csr_hmac,
)
import services.token_service as token_service

logger = logging.getLogger(__name__)

# ── File logging ──────────────────────────────────────────────────────────────
_LOG_DIR = "/opt/mpwt/logs"
try:
    os.makedirs(_LOG_DIR, exist_ok=True)
    _fh = logging.FileHandler(os.path.join(_LOG_DIR, "enrollment-errors.log"))
    _fh.setLevel(logging.DEBUG)
    _fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    ))
    logging.getLogger().addHandler(_fh)
    logging.getLogger().setLevel(logging.DEBUG)
except OSError:
    pass

enroll_bp = Blueprint("enroll", __name__)

CN_PREFIX        = "MPWT-"
CN_PATTERN       = re.compile(r"^MPWT-[A-Z0-9]+$")
_MAX_DEVICE_NAME = 64

def _employee_device_order(employee_id, device_id):
    row = database.query_one(
        """
        SELECT COUNT(*) AS count
        FROM devices
        WHERE employee_id = %s
          AND id <= %s
        """,
        (employee_id, device_id),
    )
    return int(row["count"])


def _expected_cn(employee_id: str) -> str:
    return f"{CN_PREFIX}{employee_id}"


def _sanitize_device_name(raw: str) -> str:
    cleaned = re.sub(r"[^\x20-\x7E]", "", raw).strip()
    return cleaned[:_MAX_DEVICE_NAME]


def _fallback_device_name(os_type: str, employee_id: str) -> str:
    return f"{os_type.capitalize()}-{employee_id}"


def _get_ca() -> CaService:
    if not hasattr(g, "_ca_service"):
        pki_base = current_app.config.get("PKI_BASE", "/opt/mpwt/pki")
        logger.debug("CaService init with PKI_BASE=%s", pki_base)
        g._ca_service = CaService({"PKI_BASE": pki_base})
    return g._ca_service


# ── /api/bot/verify-token ─────────────────────────────────────────────────────

@enroll_bp.route("/api/bot/verify-token", methods=["POST"])
def verify_token():
    data  = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()

    if not token:
        return jsonify({"error": "token required"}), 400

    row = token_service.TokenService(token)
    if row is None:
        logger.info("verify-token: not found/expired token=%.8s…", token)
        return jsonify({"error": "invalid token"}), 404

    sites = token_service.get_device_sites(row["id"])

    return jsonify({
        "employee_id": row["employee_id"],
        "full_name":   row["full_name"],
        "device_id":   row["id"],
        "device_name": row.get("device_name") or "",
        "sites":       [s["hostname"] for s in sites],
    }), 200


# ── /api/bot/config-file ──────────────────────────────────────────────────────

@enroll_bp.route("/api/bot/config-file", methods=["POST"])
def get_config_file():
    data    = request.get_json(silent=True) or {}
    token   = (data.get("token")   or "").strip()
    os_type = (data.get("os_type") or "").strip().lower()

    if not token:
        return jsonify({"error": "token required"}), 400
    if os_type not in ("windows", "macos", "linux"):
        return jsonify({"error": "os_type must be windows, macos, or linux"}), 400

    row = token_service.TokenService(token)
    if row is None:
        return jsonify({"error": "invalid or expired token"}), 404

    try:
        employee_id  = row["employee_id"]
        device_id    = row["id"]
        device_order = _employee_device_order(employee_id, device_id)
        cn           = _expected_cn(employee_id)

        content, filename = generate_config_file(
            token,
            employee_id,
            cn,
            os_type,
            device_order,
        )

        run_cmd = get_run_command(
            os_type,
            employee_id,
            device_order,
            cn,
        )
    except Exception:
        logger.exception("Config file generation failed")
        return jsonify(
            {"error": "Server configuration error. Contact IT admin."}
        ), 500

    return jsonify({
        "filename":    filename,
        "content":     content,
        "run_command": run_cmd,
    }), 200


# ── /api/bot/enroll ───────────────────────────────────────────────────────────

@enroll_bp.route("/api/bot/enroll", methods=["POST"])
def enroll():
    """Always returns JSON, even on unhandled exceptions."""
    try:
        return _enroll_impl()
    except Exception as e:
        logger.exception("Unhandled exception in /api/bot/enroll: %s", e)
        return jsonify({
            "error": "Internal server error during enrollment. Contact IT admin.",
            "reason": str(e),
        }), 500


def _enroll_impl():
    data    = request.get_json(silent=True) or {}
    token   = (data.get("token")   or "").strip()
    csr_pem = (data.get("csr")     or "").strip()
    os_type = (data.get("os_type") or "unknown").strip().lower()

    logger.debug(
        "enroll request: token=%.8s… os_type=%s csr_len=%d",
        token, os_type, len(csr_pem),
    )

    # ── Basic validation ──────────────────────────────────────────────────────
    if not token:
        return jsonify({"error": "token required"}), 400
    if not csr_pem:
        return jsonify({"error": "csr required"}), 400

    has_begin = ("-----BEGIN CERTIFICATE REQUEST-----"     in csr_pem or
                 "-----BEGIN NEW CERTIFICATE REQUEST-----" in csr_pem)
    has_end   = ("-----END CERTIFICATE REQUEST-----"       in csr_pem or
                 "-----END NEW CERTIFICATE REQUEST-----"   in csr_pem)
    if not (has_begin and has_end):
        return jsonify({"error": "csr must be PEM-encoded"}), 400

    csr_pem = (
        csr_pem
        .replace("-----BEGIN NEW CERTIFICATE REQUEST-----",
                 "-----BEGIN CERTIFICATE REQUEST-----")
        .replace("-----END NEW CERTIFICATE REQUEST-----",
                 "-----END CERTIFICATE REQUEST-----")
    )

    if os_type not in ("windows", "macos", "linux", "unknown"):
        os_type = "unknown"

    # ── Token lookup ──────────────────────────────────────────────────────────
    row = token_service.TokenService(token)
    if row is None:
        used_row = database.query_one(
            "SELECT id, employee_id, token_status FROM devices WHERE enroll_token = %s",
            (token,),
        )
        if used_row and used_row.get("token_status") == "USED":
            logger.info("enroll: token already used for device=%s", used_row["id"])
            return jsonify({
                "error": (
                    "This token has already been used. "
                    "Your device may already be enrolled. "
                    "Contact IT admin if you need a new token."
                )
            }), 410
        logger.warning("enroll: invalid/expired token=%.8s…", token)
        return jsonify({"error": "invalid or expired token"}), 404

    employee_id = row["employee_id"]
    device_id   = row["id"]
    expected_cn = _expected_cn(employee_id)

    logger.info(
        "enroll: device_id=%s employee_id=%s os=%s expected_cn=%s",
        device_id, employee_id, os_type, expected_cn,
    )

    # ── Initialise CA ─────────────────────────────────────────────────────────
    try:
        ca = _get_ca()
    except RuntimeError as e:
        logger.error("CaService init failed: %s", e)
        return jsonify({"error": "PKI configuration error. Contact IT admin."}), 500

    # ── Validate CSR CN ───────────────────────────────────────────────────────
    try:
        csr_cn = ca.extract_cn_from_csr(csr_pem)
        logger.debug("CSR CN: %r  expected: %r", csr_cn, expected_cn)
    except ValueError as e:
        return jsonify({"error": f"CSR parse error: {e}"}), 400

    if csr_cn != expected_cn:
        logger.warning(
            "CSR CN mismatch device=%s: got=%r expected=%r",
            device_id, csr_cn, expected_cn,
        )
        _audit_tamper(employee_id, device_id, "CN_MISMATCH",
                      f"got={csr_cn!r} expected={expected_cn!r}",
                      request.remote_addr)
        return jsonify({
            "error": (
                f"CSR CN must be '{expected_cn}' — got '{csr_cn}'. "
                "Re-generate the CSR using the config file provided by the bot."
            )
        }), 422

    # ── HMAC validation ───────────────────────────────────────────────────────
    os_types_to_try = [os_type] if os_type != "unknown" else ["windows", "macos", "linux"]
    hmac_valid      = False
    matched_os      = os_type

    for try_os in os_types_to_try:
        if verify_csr_hmac(csr_pem, token, employee_id, expected_cn, try_os):
            hmac_valid  = True
            matched_os  = try_os
            break

    if not hmac_valid:
        logger.warning(
            "HMAC validation failed device=%s employee=%s — "
            "CSR not generated from server-issued config file.",
            device_id, employee_id,
        )
        _audit_tamper(employee_id, device_id, "HMAC_FAIL",
                      "ChallengePassword missing or wrong", request.remote_addr)
        return jsonify({
            "error": (
                "This CSR was not generated from the official MPWT enrollment config file. "
                "Please use the config file sent by the bot and do not modify it."
            )
        }), 422

    if matched_os != os_type and os_type != "unknown":
        logger.info(
            "HMAC matched on os=%s but bot reported os=%s for device=%s",
            matched_os, os_type, device_id,
        )

    # ── Extract device hostname from CSR OU ───────────────────────────────────
    try:
        device_name = _extract_hostname_ou(csr_pem, ca)
    except Exception as e:
        logger.warning("OU extraction failed device=%s: %s", device_id, e)
        device_name = ""

    if not device_name:
        device_name = _fallback_device_name(matched_os, employee_id)
        logger.info("device_name: fallback=%r device=%s", device_name, device_id)
    else:
        logger.info("device_name: from CSR OU=%r device=%s", device_name, device_id)

    # ── Revoke any previous active cert ───────────────────────────────────────
    existing_serial = _get_active_cert_serial(device_id)
    if existing_serial:
        logger.info("Revoking old cert serial=%s device=%s", existing_serial, device_id)
        try:
            ca.revoke_certificate(existing_serial)
        except Exception as e:
            logger.error("Revocation failed serial=%s: %s", existing_serial, e)

    # ── Sign the CSR ──────────────────────────────────────────────────────────
    try:
        signed_cert_pem, serial_hex = ca.sign_csr(csr_pem, employee_id=employee_id)
    except Exception as e:
        logger.exception("CA signing failed device=%s: %s", device_id, e)
        return jsonify({"error": "Certificate signing failed. Contact IT admin."}), 500

    ca_chain_pem = ca.get_ca_chain_pem()

    # ── Persist to database ───────────────────────────────────────────────────
    try:
        token_service.consume_token(device_id)

        logger.info(
            "DB UPDATE: serial=%r device_name=%r os=%r device_id=%r",
            serial_hex, device_name, matched_os, device_id,
        )

        database.execute_db(
            """
            UPDATE devices
            SET cert_serial = %s,
                cert_status = 'ACTIVE',
                device_name = %s,
                os_type     = %s,
                enrolled_at = NOW(),
                updated_at  = NOW()
            WHERE id = %s
            """,
            (serial_hex, device_name, matched_os, device_id),
        )

        database.execute_db(
            """
            INSERT INTO audit_log
              (event, employee_id, device_id, device_name, detail, ip_address)
            VALUES ('CERT_ISSUED', %s, %s, %s, %s, %s)
            """,
            (
                employee_id,
                device_id,
                device_name,
                f"serial={serial_hex} cn={csr_cn} os={matched_os}",
                request.remote_addr,
            ),
        )
    except Exception as e:
        logger.exception("DB error after cert issuance device=%s: %s", device_id, e)

        try:
            ca.revoke_certificate(serial_hex)
        except Exception:
            pass

        return jsonify({
            "error":  "Database error",
            "reason": str(e),
        }), 500

    logger.info(
        "Enrollment complete: device_id=%s employee_id=%s serial=%s "
        "device_name=%r os=%s",
        device_id, employee_id, serial_hex, device_name, matched_os,
    )

    return jsonify({
        "client_crt":   signed_cert_pem,
        "ca_chain_crt": ca_chain_pem,
        "serial":       serial_hex,
        "device_name":  device_name,
    }), 200


# ── /api/auth-check ───────────────────────────────────────────────────────────

@enroll_bp.route("/api/auth-check", methods=["GET"])
def auth_check():
    verify        = request.headers.get("X-SSL-Client-Verify",  "")
    serial        = request.headers.get("X-SSL-Client-Serial",   "").upper().lstrip("0")
    host          = request.headers.get("X-Forwarded-Host",      "").split(":")[0].lower()
    reported_host = request.headers.get("X-Device-Hostname",     "").strip()

    if verify != "SUCCESS":
        return "", 403
    if not serial or not host:
        return "", 403

    row = database.query_one(
        """
        SELECT d.id, d.employee_id, d.device_name
        FROM   devices d
        JOIN   device_access da ON da.device_id = d.id
        JOIN   sites s          ON s.id = da.site_id
        WHERE  d.cert_serial = %s
          AND  d.cert_status  = 'ACTIVE'
          AND  s.hostname     = %s
          AND  s.active       = true
        LIMIT  1
        """,
        (serial, host),
    )

    if not row:
        logger.info("auth-check deny: serial=%.8s… host=%s", serial, host)
        return "", 403

    if reported_host:
        enrolled_name  = (row.get("device_name") or "").lower()
        reported_short = reported_host.lower().split(".")[0]
        enrolled_short = enrolled_name.lower().split(".")[0]

        if enrolled_short and reported_short and enrolled_short != reported_short:
            logger.warning(
                "ANOMALY: device_id=%s employee=%s cert_serial=%.8s… "
                "enrolled_name=%r reported_hostname=%r host=%s",
                row["id"], row["employee_id"], serial,
                enrolled_name, reported_host, host,
            )
            database.execute_db(
                """
                INSERT INTO audit_log
                  (event, employee_id, device_id, device_name, detail, ip_address)
                VALUES ('ANOMALY_HOSTNAME_MISMATCH', %s, %s, %s, %s, %s)
                """,
                (
                    row["employee_id"],
                    row["id"],
                    enrolled_name,
                    f"enrolled={enrolled_name!r} reported={reported_host!r} site={host}",
                    request.remote_addr,
                ),
            )

    return "", 200


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_active_cert_serial(device_id: int):
    row = database.query_one(
        "SELECT cert_serial FROM devices WHERE id = %s AND cert_status = 'ACTIVE'",
        (device_id,),
    )
    return row["cert_serial"] if row else None


def _audit_tamper(
    employee_id: str, device_id: int,
    event: str, detail: str, ip: str
) -> None:
    try:
        database.execute_db(
            """
            INSERT INTO audit_log
              (event, employee_id, device_id, detail, ip_address)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (event, employee_id, device_id, detail, ip),
        )
    except Exception as e:
        logger.error("audit_tamper write failed: %s", e)


_HMAC_OU_PREFIX = "MPWT-TOKEN-"


def _extract_hostname_ou(csr_pem: str, ca) -> str:
    import subprocess, tempfile, os, re

    with tempfile.NamedTemporaryFile(
        suffix=".csr", mode="w", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(csr_pem)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ["openssl", "req", "-noout", "-subject", "-in", tmp_path],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return ""

        subject = result.stdout.strip()

        ou_values = re.findall(r"OU\s*=\s*([^,/\n]+)", subject, re.IGNORECASE)
        for ou in ou_values:
            ou = ou.strip()
            if ou.upper().startswith(_HMAC_OU_PREFIX.upper()):
                continue
            return ou

        return ""
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
