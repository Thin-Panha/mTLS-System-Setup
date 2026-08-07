"""
services/tpm_service.py — TPM Endorsement Key (EK) Attestation  (v4)
================================================================================
WHY THIS VERSION EXISTS:

v3 validated the EK certificate against a trusted vendor root bundle via
`openssl verify -CAfile`. That's the textbook approach — but it turned out
to be a dead end for a common real device in your fleet: Intel PTT
(firmware TPM, used on most modern Intel CPUs, identified by issuer CN
like "CSME ADL PTT 01SVN"). Intel does not publish the root/intermediate
certificates for this ODCA chain publicly — confirmed by Intel's own
support forum, where multiple people asked directly and Intel could not
provide them. So "verify against a trusted root" is not achievable for
these devices today, full stop — it's not a bug, the certs don't exist
publicly.

MODEL (v4) — Trust-On-First-Enrollment (TOFU) pinning:
  1. This module does STRUCTURAL validation only: the EK cert extracted
     from the CSR must parse (via openssl, tolerant of the non-canonical
     DER many real TPM certs use) and look like a plausible EK cert.
  2. The actual security control — pinning — lives in routes/enroll.py,
     which already has the devices table: on a device's first enrollment,
     its EK certificate serial is recorded (tpm_ek_serial column). On
     every subsequent enrollment for that same device_id, the EK serial
     MUST match what was recorded the first time, or the request is
     rejected as a possible device swap / replay.

HONEST LIMITATION: this proves "the same TPM cert every time for this
device_id", not "this cert was issued by a genuine silicon TPM manufacturer"
(that would require the missing Intel roots). Document this to your
stakeholders — it's tamper/swap detection, not full remote attestation.
"""

import base64
import logging
import os
import subprocess
import tempfile

from cryptography import x509

logger = logging.getLogger(__name__)

# Must match the OID used by the PowerShell enrollment script.
TPM_EK_CERT_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.1")


class TpmVerificationError(Exception):
    pass


# ── Public API ────────────────────────────────────────────────────────────────

def verify_tpm_attestation(csr_pem: str) -> tuple[bool, dict]:
    """
    Extract and structurally validate the EK certificate embedded in the
    CSR. Does NOT check a trust chain (see module docstring for why) —
    pinning against the device's previously-recorded EK serial happens in
    routes/enroll.py, which has access to the devices table.
    """
    metadata: dict = {}

    try:
        ek_cert_pem = _extract_ek_cert(csr_pem)
    except Exception as exc:
        logger.warning("EK cert extraction failed: %s", exc)
        return False, {"error": f"extraction_failed: {exc}"}

    if not ek_cert_pem:
        logger.warning("No EK certificate extension found in CSR")
        return False, {"error": "no_ek_cert_extension"}

    try:
        subject, serial = _openssl_cert_info(ek_cert_pem)
    except Exception as exc:
        logger.warning("EK certificate parse failed (openssl): %s", exc)
        return False, {"error": "ek_cert_parse_failed"}

    metadata["ek_subject"] = subject
    metadata["ek_serial"]  = serial
    metadata["tpm_verified"] = True

    logger.info("TPM EK cert structurally valid: ek_serial=%s subject=%s",
                serial, subject)
    return True, metadata


# ── Internal helpers ──────────────────────────────────────────────────────────

def _extract_ek_cert(csr_pem: str) -> str:
    """Pull the EK certificate out of the CSR's custom extension."""
    csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))

    for ext in csr.extensions:
        if ext.oid == TPM_EK_CERT_OID:
            value = ext.value
            raw = getattr(value, "value", None)
            if raw is None:
                raw = bytes(value.public_bytes())
            text = raw.decode("utf-8", errors="ignore").strip()
            if "-----BEGIN CERTIFICATE-----" in text:
                return text
            b64 = base64.b64encode(raw).decode("ascii")
            lines = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
            return f"-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n"

    return ""


def _write_temp_pem(pem_text: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".pem")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(pem_text)
    return path


def _openssl_cert_info(cert_pem: str) -> tuple[str, str]:
    """Return (subject, serial_hex) via `openssl x509`, tolerant of BER quirks."""
    path = _write_temp_pem(cert_pem)
    try:
        result = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-serial", "-in", path],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            raise TpmVerificationError(
                f"openssl x509 failed rc={result.returncode}: "
                f"{result.stderr.strip()[:300]}"
            )

        subject = ""
        serial  = ""
        for line in result.stdout.splitlines():
            if line.startswith("subject="):
                subject = line[len("subject="):].strip()
            elif line.startswith("serial="):
                serial = line[len("serial="):].strip().lower()

        if not subject:
            raise TpmVerificationError("could not parse subject from openssl output")

        return subject, serial
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
