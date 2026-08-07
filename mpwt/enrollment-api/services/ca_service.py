"""
services/ca_service.py
=======================
Manages the MPWT PKI: signing CSRs, revoking certificates, reading the CA chain.

Changes in this patch
---------------------
* Added extract_ou_from_csr(csr_pem) — extracts the OU (Organizational Unit)
  value from a CSR's Subject field.  Used by enroll.py to automatically
  capture the employee's device hostname from the CSR without any user input.
  The OS instructions tell the employee to embed their machine hostname as
  OU=<hostname> via $env:COMPUTERNAME (Windows) or $(hostname -s) (macOS/Linux).
"""

import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


class CaService:
    """Wraps OpenSSL operations for the MPWT Issuing CA."""

    def __init__(self, config: dict):
        base = config.get("PKI_BASE", "/opt/mpwt/pki")
        self.issuing_dir  = Path(base) / "issuing-ca"
        self.root_dir     = Path(base) / "root-ca"
        self.ca_key       = self.issuing_dir / "private" / "issuing-ca.key"
        self.ca_cert      = self.issuing_dir / "certs"   / "issuing-ca.crt"
        self.ca_chain     = self.issuing_dir / "certs"   / "ca-chain.crt"
        self.ca_cnf       = self.issuing_dir / "config"  / "issuing-ca.cnf"
        self.ca_crl       = self.issuing_dir / "crl"     / "issuing-ca.crl"
        self.ca_index     = self.issuing_dir / "database" / "index.txt"
        self.ca_serial    = self.issuing_dir / "database" / "serial"
        self.client_ext   = Path(base) / "templates" / "client.ext"

        for path in (self.ca_key, self.ca_cert, self.ca_chain, self.ca_cnf):
            if not path.exists():
                raise RuntimeError(f"CaService: required PKI file missing: {path}")

        logger.info("CaService initialised (issuing-ca: %s)", self.issuing_dir)

    # ── CSR subject field extraction ──────────────────────────────────────────

    def extract_cn_from_csr(self, csr_pem: str) -> str:
        """
        Return the CN value from the CSR Subject, e.g. "MPWT-EMP001".
        Raises ValueError on parse failure.
        """
        return self._extract_subject_field(csr_pem, "CN")

    def extract_ou_from_csr(self, csr_pem: str) -> str:
        """
        Return the OU (Organizational Unit) value from the CSR Subject.
        This carries the employee's machine hostname, embedded automatically
        by the OS-specific CSR generation command.

        Returns an empty string if no OU is present — callers should use
        a fallback name in that case.
        """
        try:
            return self._extract_subject_field(csr_pem, "OU")
        except ValueError:
            return ""

    def _extract_subject_field(self, csr_pem: str, field: str) -> str:
        """
        Parse an arbitrary Subject field from a PEM CSR using openssl.

        openssl req -noout -subject outputs something like:
            subject=CN=MPWT-EMP001, OU=JOHN-LAPTOP, O=MPWT, C=KH
        or (older openssl / -nameopt compat style):
            subject= /CN=MPWT-EMP001/OU=JOHN-LAPTOP/O=MPWT/C=KH

        We handle both formats.
        """
        with tempfile.NamedTemporaryFile(
            suffix=".csr", mode="w", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(csr_pem)
            tmp_path = tmp.name

        try:
            result = subprocess.run(
                ["openssl", "req", "-noout", "-subject", "-in", tmp_path],
                capture_output=True,
                text=True,
                timeout=10,
            )
        finally:
            os.unlink(tmp_path)

        if result.returncode != 0:
            raise ValueError(
                f"openssl req -subject failed (rc={result.returncode}): "
                f"{result.stderr.strip()}"
            )

        subject_line = result.stdout.strip()
        logger.debug("CSR subject line: %r", subject_line)

        # RFC 2253 / new-style: "field = VALUE" with comma separators
        # e.g.  subject=CN=MPWT-EMP001, OU=JOHN-LAPTOP, O=MPWT, C=KH
        # Legacy / slash-style:  /CN=.../OU=JOHN-LAPTOP/O=...
        #
        # Strategy: normalise to a comma list, then find field=VALUE.

        # Strip leading "subject=" or "subject= "
        subject_line = re.sub(r"^subject\s*=\s*", "", subject_line)

        # Convert slash-style to comma-style for uniform parsing
        if subject_line.startswith("/"):
            subject_line = subject_line.lstrip("/").replace("/", ", ")

        # Now match  FIELD = VALUE  (value ends at comma or end-of-string)
        pattern = re.compile(
            rf"(?:^|,\s*){re.escape(field)}\s*=\s*([^,]+)",
            re.IGNORECASE,
        )
        m = pattern.search(subject_line)
        if not m:
            raise ValueError(
                f"Field '{field}' not found in CSR Subject: {subject_line!r}"
            )

        return m.group(1).strip()

    # ── Certificate signing ───────────────────────────────────────────────────

    def sign_csr(self, csr_pem: str, employee_id: str) -> tuple[str, str]:
        """
        Sign a CSR with the Issuing CA.

        Returns (signed_cert_pem, serial_hex).
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            csr_path  = os.path.join(tmpdir, "request.csr")
            cert_path = os.path.join(tmpdir, "client.crt")
            cnf_path  = self._make_patched_cnf(tmpdir)

            with open(csr_path, "w") as f:
                f.write(csr_pem)

            cmd = [
                "openssl", "ca",
                "-config",    cnf_path,
                "-in",        csr_path,
                "-out",       cert_path,
                "-extensions", "client_cert",
                "-days",      "365",
                "-notext",
                "-batch",
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(self.issuing_dir),
            )

            if result.returncode != 0:
                logger.error(
                    "openssl ca failed rc=%d\nstdout=%s\nstderr=%s",
                    result.returncode, result.stdout, result.stderr,
                )
                raise RuntimeError(
                    f"openssl ca failed (rc={result.returncode}): "
                    f"{result.stderr.strip()}"
                )

            with open(cert_path) as f:
                cert_pem = f.read()

        serial_hex = self._extract_serial(cert_pem)
        return cert_pem, serial_hex

    def _make_patched_cnf(self, tmpdir: str) -> str:
        """
        Write a modified copy of issuing-ca.cnf that injects the [client_cert]
        extension section if it is missing — required for OpenSSL 3.0.
        """
        with open(self.ca_cnf) as f:
            cnf_text = f.read()

        if "[client_cert]" not in cnf_text:
            cnf_text += (
                "\n[client_cert]\n"
                "basicConstraints       = CA:FALSE\n"
                "nsCertType             = client, email\n"
                "nsComment              = 'MPWT Client Certificate'\n"
                "subjectKeyIdentifier   = hash\n"
                "authorityKeyIdentifier = keyid,issuer\n"
                "keyUsage               = critical, nonRepudiation, digitalSignature, keyEncipherment\n"
                "extendedKeyUsage       = clientAuth, emailProtection\n"
            )

        patched_path = os.path.join(tmpdir, "issuing-ca-patched.cnf")
        with open(patched_path, "w") as f:
            f.write(cnf_text)
        return patched_path

    # ── Certificate revocation ────────────────────────────────────────────────

    def revoke_certificate(self, serial_hex: str) -> None:
        """Revoke a certificate by its hex serial and update the CRL."""
        # Find the cert file in the issued certs directory
        cert_path = self.issuing_dir / "certs" / f"{serial_hex.upper()}.pem"
        if not cert_path.exists():
            # Try lowercase
            cert_path = self.issuing_dir / "certs" / f"{serial_hex.lower()}.pem"
        if not cert_path.exists():
            logger.warning("revoke: cert file not found for serial=%s", serial_hex)
            return

        result = subprocess.run(
            [
                "openssl", "ca",
                "-config", str(self.ca_cnf),
                "-revoke", str(cert_path),
                "-batch",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(self.issuing_dir),
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"openssl ca -revoke failed (rc={result.returncode}): "
                f"{result.stderr.strip()}"
            )

        # Regenerate the CRL
        subprocess.run(
            [
                "openssl", "ca",
                "-config", str(self.ca_cnf),
                "-gencrl",
                "-out", str(self.ca_crl),
                "-batch",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(self.issuing_dir),
            check=True,
        )
        logger.info("CRL updated after revocation of serial=%s", serial_hex)

    # ── CA chain ─────────────────────────────────────────────────────────────

    def get_ca_chain_pem(self) -> str:
        with open(self.ca_chain) as f:
            return f.read()

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_serial(cert_pem: str) -> str:
        """
        Extract the hex serial number from a signed PEM certificate.
        """
        with tempfile.NamedTemporaryFile(
            suffix=".crt", mode="w", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(cert_pem)
            tmp_path = tmp.name

        try:
            result = subprocess.run(
                ["openssl", "x509", "-noout", "-serial", "-in", tmp_path],
                capture_output=True,
                text=True,
                timeout=10,
            )
        finally:
            os.unlink(tmp_path)

        if result.returncode != 0:
            raise RuntimeError(
                f"openssl x509 -serial failed: {result.stderr.strip()}"
            )

        # Output: "serial=AABBCCDD"
        m = re.search(r"serial=([0-9A-Fa-f]+)", result.stdout)
        if not m:
            raise RuntimeError(
                f"Could not parse serial from: {result.stdout!r}"
            )
        return m.group(1).upper()
