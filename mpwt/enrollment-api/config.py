import os

def _read_credential(name: str) -> str | None:
    """Read a secret from systemd's LoadCredentialEncrypted directory, if present."""
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if not cred_dir:
        return None
    path = os.path.join(cred_dir, name)
    if not os.path.isfile(path):
        return None
    with open(path, "r") as f:
        return f.read().strip()

def _require(key: str, cred_name: str | None = None) -> str:
    # Prefer systemd credential file, fall back to plain env var
    value = _read_credential(cred_name or key.lower()) or os.environ.get(key, "")
    if not value:
        raise RuntimeError(
            f"Required secret '{key}' is not set. "
            "Check LoadCredentialEncrypted in the systemd unit file."
        )
    return value

# Flask
SECRET_KEY   = _require("SECRET_KEY",   "secret_key")
MPWT_API_KEY = _require("MPWT_API_KEY", "mpwt_api_key_enroll")

# PostgreSQL
DB_HOST     = os.environ.get("DB_HOST", "127.0.0.1")
DB_PORT     = os.environ.get("DB_PORT", "5432")
DB_NAME     = os.environ.get("DB_NAME", "mpwt")
DB_USER     = os.environ.get("DB_USER", "mpwt")
DB_PASSWORD = _require("DB_PASSWORD", "db_password")

DATABASE_URL = (
    f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)

# PKI paths
PKI_BASE         = os.environ.get("PKI_BASE", "/opt/mpwt/pki")
ISSUING_CA_CNF   = f"{PKI_BASE}/issuing-ca/config/issuing-ca.cnf"
ISSUING_CA_CRT   = f"{PKI_BASE}/issuing-ca/certs/issuing-ca.crt"
ISSUING_CA_KEY   = f"{PKI_BASE}/issuing-ca/private/issuing-ca.key"
CA_CHAIN_CRT     = f"{PKI_BASE}/issuing-ca/certs/ca-chain.crt"
ISSUING_CA_CRL   = f"{PKI_BASE}/issuing-ca/crl/issuing-ca.crl"

NGINX_CRL_PATH   = "/etc/nginx/ssl/certs/issuing-ca.crl"

CLIENT_EXT       = f"{PKI_BASE}/templates/client.ext"

TOKEN_EXPIRY_HOURS = int(os.environ.get("TOKEN_EXPIRY_HOURS", "48"))

LOG_PATH = os.environ.get("LOG_PATH", "/opt/mpwt/logs/enrollment-api.log")
