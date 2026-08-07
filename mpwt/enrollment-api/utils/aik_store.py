"""
utils/aik_store.py — registered AIK public keys, keyed by employee_id.

This is the trust anchor for TPM attestation (policy_service.verify_csr_tpm).
An AIK is only useful once you already trust it belongs to a specific
device/employee -- that trust has to be established out-of-band, once,
during device provisioning (e.g. IT staff physically registers a new
laptop's AIK before it ever gets an enrollment token).

Swap _load_raw/_save_raw for a real DB table if you outgrow a flat file --
the public API (get/register/revoke) doesn't need to change.

Schema (aik_registry.json):
{
  "EMP001": {
    "public_key_pem": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----\\n",
    "registered_at":  "2026-07-02 10:00",
    "registered_by":  "it-admin-name",
    "note":           "Dell Latitude 5540, asset tag DT-1183"
  }
}
"""

import json
import logging
import os
import tempfile
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Self-contained on purpose: this module lives in enrollment-api, which may
# not share a config module with the telegram-bot. Override the path with
# an env var in the systemd unit if you want it somewhere else.
_REGISTRY_PATH = os.environ.get(
    "MPWT_AIK_REGISTRY_PATH",
    "/opt/mpwt/enrollment-api/data/aik_registry.json",
)


def _load_raw() -> dict:
    if not os.path.exists(_REGISTRY_PATH):
        return {}
    try:
        with open(_REGISTRY_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error("aik_registry.json read error (%s) — treating as empty", e)
        return {}


def _save_raw(data: dict) -> None:
    os.makedirs(os.path.dirname(_REGISTRY_PATH) or ".", exist_ok=True)
    dir_ = os.path.dirname(os.path.abspath(_REGISTRY_PATH))
    fd, tmp = tempfile.mkstemp(dir=dir_, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, _REGISTRY_PATH)
    except OSError as e:
        logger.error("aik_registry.json write error: %s", e)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def get_registered_aik_public_key(employee_id: str) -> bytes | None:
    """Return the PEM-encoded AIK public key bytes for employee_id, or None."""
    entry = _load_raw().get(employee_id)
    if not entry:
        return None
    return entry["public_key_pem"].encode("utf-8")


def register_aik_public_key(
    employee_id: str,
    public_key_pem: str,
    registered_by: str,
    note: str = "",
) -> None:
    """
    Record an AIK as trusted for this employee. Call this ONCE, during
    device provisioning, over a channel you already trust (e.g. IT admin
    running a CLI on-site) -- never in response to an unauthenticated
    enrollment request, or the whole attestation layer is meaningless.
    """
    data = _load_raw()
    data[employee_id] = {
        "public_key_pem": public_key_pem,
        "registered_at":  datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
        "registered_by":  registered_by,
        "note":           note,
    }
    _save_raw(data)
    logger.info("AIK registered for employee=%s by=%s", employee_id, registered_by)


def revoke_aik(employee_id: str) -> bool:
    """Remove a registered AIK (e.g. device decommissioned/lost)."""
    data = _load_raw()
    if employee_id in data:
        del data[employee_id]
        _save_raw(data)
        logger.info("AIK revoked for employee=%s", employee_id)
        return True
    return False
