"""
MPWT Enrollment Agent — Windows
Compiled to single .exe by IT admin on Ubuntu server.
Employee receives one .exe file. Double-click. Done.
"""

import json
import os
import sys
import socket
import platform
import logging
import ctypes
import subprocess
import tempfile
from pathlib import Path

import requests
from cryptography.hazmat.primitives             import serialization
from cryptography.hazmat.primitives.asymmetric  import rsa
from cryptography.hazmat.primitives.hashes      import SHA256
from cryptography.hazmat.backends               import default_backend
from cryptography                               import x509
from cryptography.x509                          import (
    CertificateSigningRequestBuilder,
    NameOID,
)
from cryptography.hazmat.primitives.serialization import pkcs12

# ------------------------------------------------------------------ #
#  Runtime path — MUST be first                                        #
# ------------------------------------------------------------------ #

def get_base_path() -> Path:
    if getattr(sys, "frozen", False):
        if hasattr(sys, "_MEIPASS"):
            return Path(sys._MEIPASS)
        return Path(sys.executable).parent
    return Path(__file__).parent

BASE = get_base_path()

# ------------------------------------------------------------------ #
#  Logging                                                             #
# ------------------------------------------------------------------ #

LOG_DIR = Path(os.environ.get("APPDATA", tempfile.gettempdir())) / "MPWT"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_PATH = LOG_DIR / "agent.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("mpwt-agent")

# ------------------------------------------------------------------ #
#  UI helpers                                                          #
# ------------------------------------------------------------------ #

def show_message(title: str, msg: str, error: bool = False):
    icon = 0x10 if error else 0x40
    ctypes.windll.user32.MessageBoxW(0, msg, title, icon | 0x1000)

def show_progress(step: str):
    ctypes.windll.kernel32.SetConsoleTitleW(f"MPWT Enrollment — {step}")

# ------------------------------------------------------------------ #
#  Config loading — with full diagnostics                              #
# ------------------------------------------------------------------ #

def load_config() -> dict:
    config_path = BASE / "agent-config.json"
    ca_path     = BASE / "ca-chain.crt"

    # Always log diagnostics first
    logger.info("frozen     : %s", getattr(sys, 'frozen', False))
    logger.info("_MEIPASS   : %s", getattr(sys, '_MEIPASS', 'N/A'))
    logger.info("executable : %s", sys.executable)
    logger.info("BASE       : %s", BASE)
    logger.info("config     : %s  exists=%s", config_path, config_path.exists())
    logger.info("ca-chain   : %s  exists=%s", ca_path, ca_path.exists())

    try:
        files = sorted(BASE.iterdir())
        logger.info("BASE contents (%d items):", len(files))
        for f in files:
            logger.info("  %s", f.name)
    except Exception as e:
        logger.warning("Cannot list BASE: %s", e)

    if not config_path.exists():
        raise FileNotFoundError(
            f"agent-config.json not found at:\n{config_path}\n\n"
            f"BASE = {BASE}\n\n"
            f"This is a build problem — contact IT support.\n"
            f"Log: {LOG_PATH}"
        )

    with open(config_path, encoding="utf-8") as f:
        config = json.load(f)

    # Always resolve ca_cert relative to BASE (ignore whatever is in JSON)
    config["ca_cert"] = str(ca_path)

    logger.info("Config loaded: employee=%s url=%s",
                config.get("employee_id"), config.get("enrollment_url"))
    return config

# ------------------------------------------------------------------ #
#  Device identity                                                     #
# ------------------------------------------------------------------ #

def get_device_name() -> str:
    return socket.gethostname().upper()

# ------------------------------------------------------------------ #
#  Key generation                                                      #
# ------------------------------------------------------------------ #

def generate_private_key():
    logger.info("Generating 2048-bit RSA key pair on this device...")
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

def generate_csr(private_key, employee_id: str, device_name: str) -> bytes:
    logger.info("Creating Certificate Signing Request for %s / %s",
                employee_id, device_name)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,             "KH"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,        "MPWT"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, employee_id),
        x509.NameAttribute(NameOID.COMMON_NAME,              device_name),
    ])
    csr = (
        CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, SHA256(), default_backend())
    )
    return csr.public_bytes(serialization.Encoding.PEM)

# ------------------------------------------------------------------ #
#  Enrollment API call                                                 #
# ------------------------------------------------------------------ #

def send_csr(config: dict, csr_pem: bytes, device_name: str) -> dict:
    ca_cert_path = config["ca_cert"]
    url          = config["enrollment_url"]

    logger.info("CA cert path : %s  exists=%s", ca_cert_path,
                Path(ca_cert_path).exists())
    logger.info("Sending CSR to: %s", url)

    payload = {
        "token":       config["token"],
        "csr":         csr_pem.decode("utf-8"),
        "device_name": device_name,
        "employee_id": config["employee_id"],
    }

    resp = requests.post(url, json=payload, verify=ca_cert_path, timeout=30)

    if resp.status_code != 200:
        raise RuntimeError(f"Server returned {resp.status_code}:\n{resp.text}")

    data = resp.json()
    if data.get("status") != "success":
        raise RuntimeError(data.get("message", "Unknown server error"))

    return data

# ------------------------------------------------------------------ #
#  Windows Certificate Store installation                              #
# ------------------------------------------------------------------ #

def install_to_windows_store(
    cert_pem: str,
    private_key,
    ca_chain_pem: str,
    employee_id: str,
) -> str:
    logger.info("Installing certificates into Windows store...")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        # Install CA chain
        ca_certs = _split_pem_chain(ca_chain_pem)
        for i, ca_pem in enumerate(ca_certs):
            ca_path = tmp / f"ca-{i}.crt"
            ca_path.write_text(ca_pem, encoding="utf-8")
            store = "Root" if i == len(ca_certs) - 1 else "CA"
            logger.info("Installing CA cert %d → %s store", i + 1, store)
            _certutil_add(str(ca_path), store)

        # Build PFX entirely in Python — no OpenSSL, no PowerShell CNG needed
        logger.info("Building PKCS#12 bundle in Python...")
        cert_obj = x509.load_pem_x509_certificate(
            cert_pem.encode("utf-8"), default_backend()
        )

        pfx_bytes = pkcs12.serialize_key_and_certificates(
            name=f"MPWT-Device-{employee_id}".encode("utf-8"),
            key=private_key,
            cert=cert_obj,
            cas=None,
            encryption_algorithm=serialization.NoEncryption(),
        )

        pfx_path = tmp / "client.pfx"
        pfx_path.write_bytes(pfx_bytes)
        logger.info("PFX written: %d bytes", len(pfx_bytes))

        # Import into Windows Personal store (non-exportable)
        logger.info("Importing PFX into CurrentUser\\My store...")
        ps_cmd = (
            f'$cert = Import-PfxCertificate '
            f'-FilePath "{pfx_path}" '
            f'-CertStoreLocation "Cert:\\CurrentUser\\My" '
            f'-Exportable:$false; '
            f'Write-Output $cert.Thumbprint'
        )
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"PFX import failed:\n{result.stderr}\n\n"
                "Try running as Administrator."
            )

        thumbprint = result.stdout.strip()
        logger.info("Certificate installed. Thumbprint: %s", thumbprint)
        return thumbprint


def _split_pem_chain(chain_pem: str) -> list:
    certs, current = [], []
    for line in chain_pem.splitlines():
        if line.startswith("-----BEGIN"):
            current = [line]
        elif line.startswith("-----END"):
            current.append(line)
            certs.append("\n".join(current))
            current = []
        elif current:
            current.append(line)
    return certs


def _certutil_add(cert_path: str, store: str):
    result = subprocess.run(
        ["certutil", "-addstore", "-f", store, cert_path],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        logger.warning("certutil %s: %s", store, result.stderr.strip())
    else:
        logger.info("certutil %s: OK", store)

# ------------------------------------------------------------------ #
#  Main                                                                #
# ------------------------------------------------------------------ #

def main():
    logger.info("=" * 60)
    logger.info("MPWT Enrollment Agent v2.0")
    logger.info("Platform  : %s %s", platform.system(), platform.version())
    logger.info("Log       : %s", LOG_PATH)
    logger.info("=" * 60)

    try:
        show_progress("Loading config...")
        config      = load_config()
        employee_id = config["employee_id"].upper()
        device_name = get_device_name()

        logger.info("Employee : %s", employee_id)
        logger.info("Device   : %s", device_name)

        show_progress("Generating key pair...")
        private_key = generate_private_key()
        csr_pem     = generate_csr(private_key, employee_id, device_name)

        show_progress("Contacting enrollment server...")
        result = send_csr(config, csr_pem, device_name)

        cert_pem     = result["certificate"]
        ca_chain_pem = result["ca_chain"]
        serial       = result["serial"]
        not_after    = result["not_after"]

        logger.info("Certificate received — serial=%s expires=%s",
                    serial, not_after[:10])

        show_progress("Installing certificate...")
        thumbprint = install_to_windows_store(
            cert_pem, private_key, ca_chain_pem, employee_id
        )

        del private_key
        del cert_pem

        show_progress("Complete!")
        logger.info("Enrollment COMPLETE — thumbprint: %s", thumbprint)

        show_message(
            "MPWT Enrollment Complete",
            f"Device enrolled successfully.\n\n"
            f"Employee : {employee_id}\n"
            f"Device   : {device_name}\n"
            f"Serial   : {serial}\n"
            f"Expires  : {not_after[:10]}\n\n"
            f"You can now open:\n"
            f"  https://dev.mpwt.local\n\n"
            f"Log: {LOG_PATH}",
            error=False,
        )

    except FileNotFoundError as e:
        logger.error("Config error: %s", e)
        show_message("MPWT Enrollment Failed",
                     f"Configuration error:\n\n{e}", error=True)

    except RuntimeError as e:
        logger.error("Enrollment failed: %s", e)
        show_message("MPWT Enrollment Failed",
                     f"Enrollment failed:\n\n{e}\n\nLog: {LOG_PATH}",
                     error=True)

    except Exception as e:
        logger.exception("Unexpected error")
        show_message("MPWT Enrollment Failed",
                     f"Unexpected error:\n{type(e).__name__}: {e}\n\nLog: {LOG_PATH}",
                     error=True)


if __name__ == "__main__":
    main()
