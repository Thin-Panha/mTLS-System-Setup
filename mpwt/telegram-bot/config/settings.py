"""
Central config — reads environment variables from the systemd service unit,
falling back to systemd-creds encrypted credentials for secrets.

Required (one of): TELEGRAM_BOT_TOKEN env var OR telegram_token credential
Required (one of): MPWT_API_KEY env var OR mpwt_api_key credential

Optional env vars:
    MPWT_API_BASE           — enrollment backend URL
                              default: https://auth.mpwt.local
    MPWT_CA_CERT            — path to CA bundle (issuing CA + root CA)
                              default: /opt/mpwt/pki/issuing-ca/certs/ca-chain.crt
    WHITELIST_PATH          — path to whitelist.txt
                              default: /opt/mpwt/telegram-bot/whitelist.txt
    STATE_PATH              — path to state.json
                              default: /opt/mpwt/telegram-bot/state.json
    RATE_WINDOW_SECONDS     — sliding window for rate limiting (default: 60)
    RATE_MAX_ATTEMPTS       — max attempts before block (default: 5)
    RATE_BLOCK_DURATION     — block duration in seconds (default: 3600 = 1 hour)
"""

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


class _Settings:
    # ── Telegram ───────────────────────────────────────────────────────────────
    TELEGRAM_TOKEN: str = _read_credential("telegram_token") or os.environ.get("TELEGRAM_BOT_TOKEN", "")

    # ── Backend ────────────────────────────────────────────────────────────────
    API_BASE: str = os.environ.get("MPWT_API_BASE", "https://auth.mpwt.local")
    API_KEY:  str = _read_credential("mpwt_api_key_bot") or os.environ.get("MPWT_API_KEY", "")

    # CA bundle: issuing CA cert + root CA cert concatenated into one file
    CA_CERT: str = os.environ.get(
        "MPWT_CA_CERT",
        "/opt/mpwt/pki/issuing-ca/certs/ca-chain.crt",
    )

    # ── Whitelist ──────────────────────────────────────────────────────────────
    WHITELIST_PATH: str = os.environ.get(
        "WHITELIST_PATH",
        "/opt/mpwt/telegram-bot/whitelist.txt",
    )

    # ── State ──────────────────────────────────────────────────────────────────
    STATE_PATH: str = os.environ.get(
        "STATE_PATH",
        "/opt/mpwt/telegram-bot/state.json",
    )

    # ── Rate limiting (unauthorized users only) ────────────────────────────────
    RATE_WINDOW_SECONDS: int = int(os.environ.get("RATE_WINDOW_SECONDS", "60"))
    RATE_MAX_ATTEMPTS:   int = int(os.environ.get("RATE_MAX_ATTEMPTS",   "5"))
    RATE_BLOCK_DURATION: int = int(os.environ.get("RATE_BLOCK_DURATION", "3600"))

    if not TELEGRAM_TOKEN:
        raise RuntimeError("TELEGRAM_TOKEN not found in credentials or environment.")


settings = _Settings()
