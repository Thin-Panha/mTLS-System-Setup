#!/usr/bin/env bash
# lib/common.sh
# ---------------------------------------------------------------------------
# Shared helpers for create-certificate.sh and encrypt-secrets.sh.
# Source this file; do not execute it directly.
# ---------------------------------------------------------------------------

# ============================================================================
# Paths -- override any of these via environment variables before sourcing
# ============================================================================
REPO_ROOT="${REPO_ROOT:-/opt/mpwt}"
PKI_ROOT="${PKI_ROOT:-${REPO_ROOT}/pki}"
ISSUING_CA_DIR="${ISSUING_CA_DIR:-${PKI_ROOT}/issuing-ca}"
ISSUING_CA_CNF="${ISSUING_CA_CNF:-${ISSUING_CA_DIR}/config/issuing-ca.cnf}"
ROOT_CA_CERT="${ROOT_CA_CERT:-${PKI_ROOT}/root-ca/certs/root-ca.cert.pem}"
ISSUING_CA_CERT="${ISSUING_CA_CERT:-${ISSUING_CA_DIR}/certs/issuing-ca.cert.pem}"
KEY_OUT_DIR="${KEY_OUT_DIR:-${ISSUING_CA_DIR}/private}"
CERT_OUT_DIR="${CERT_OUT_DIR:-${ISSUING_CA_DIR}/certs}"

CREDS_DIR="${CREDS_DIR:-/etc/mpwt/creds}"
INPUT_ENV_FILE="${INPUT_ENV_FILE:-${SCRIPT_DIR}/provision.env}"

SERVICE_USER="${SERVICE_USER:-${SUDO_USER:-$(id -un)}}"
LOG_FILE="${LOG_FILE:-/var/log/mpwt/provision.log}"   # NO secrets ever written here

UMASK_SECURE=077

# ============================================================================
# Logging / error handling
# ============================================================================
umask "${UMASK_SECURE}"

mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true

log() {
  echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $*" | tee -a "${LOG_FILE}" >&2
}

die() {
  log "ERROR: $*"
  echo "ERROR: $*" >&2
  exit 1
}

require_root() {
  [[ "${EUID}" -eq 0 ]] || die "This script must be run as root."
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command '$1' not found in PATH."
}

require_service_user() {
  id -u "${SERVICE_USER}" >/dev/null 2>&1 || die "Service user '${SERVICE_USER}' does not exist. Create it first: adduser --system --group ${SERVICE_USER}"
}

# ============================================================================
# provision.env parsing -- plain text KEY=VALUE, never sourced/executed
# ============================================================================
read_env_value() {
  local key="$1" file="$2" line val
  [[ -f "${file}" ]] || return 1
  line="$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "${file}" | tail -n1 || true)"
  [[ -n "${line}" ]] || return 1
  val="${line#*=}"
  val="${val%%[[:space:]]#*}"
  val="$(printf '%s' "${val}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  val="${val%\"}"; val="${val#\"}"
  val="${val%\'}"; val="${val#\'}"
  printf '%s' "${val}"
}

ensure_input_file_perms() {
  [[ -f "${INPUT_ENV_FILE}" ]] || return 0
  local perms
  perms="$(stat -c '%a' "${INPUT_ENV_FILE}" 2>/dev/null || stat -f '%Lp' "${INPUT_ENV_FILE}")"
  if [[ "${perms}" != "600" && "${perms}" != "400" ]]; then
    log "WARNING: ${INPUT_ENV_FILE} permissions are ${perms}, expected 600. Tightening now."
    chmod 600 "${INPUT_ENV_FILE}"
  fi
}

# ============================================================================
# Validation
# ============================================================================
valid_domain() {
  local d="$1"
  [[ "$d" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$ ]]
}

valid_telegram_token() {
  local t="$1"
  [[ "$t" =~ ^[0-9]{6,}:[A-Za-z0-9_-]{30,}$ ]]
}

# ============================================================================
# Interactive fallback prompts (hidden input, never logged)
# ============================================================================
prompt_domain() {
  while true; do
    read -r -p "Enter the server domain / FQDN for the certificate (e.g. auth.mpwt.local): " DOMAIN
    valid_domain "${DOMAIN}" && break
    echo "  -> Invalid domain format. Try again."
  done
}

prompt_telegram_token() {
  while true; do
    read -r -s -p "Enter Telegram bot token (from @BotFather): " TELEGRAM_BOT_TOKEN; echo
    valid_telegram_token "${TELEGRAM_BOT_TOKEN}" && break
    echo "  -> Doesn't look like a valid Telegram bot token (expected NNNNNNN:xxxxxxxx). Try again."
  done
}

# prompt_secret <var_name> <label> <allow_autogen: true|false> [hex_bytes]
prompt_secret() {
  local var_name="$1" label="$2" allow_autogen="${3:-false}" bytes="${4:-48}"
  local s1="" s2=""
  while true; do
    if [[ "${allow_autogen}" == "true" ]]; then
      read -r -s -p "${label} (leave blank to auto-generate a strong secret): " s1; echo
    else
      read -r -s -p "${label}: " s1; echo
    fi
    if [[ -z "${s1}" && "${allow_autogen}" == "true" ]]; then
      s1="$(openssl rand -hex "${bytes}")"
      printf -v "${var_name}" '%s' "${s1}"
      echo "  -> Auto-generated ${label}."
      return 0
    fi
    if [[ -z "${s1}" ]]; then
      echo "  -> This value is required and cannot be empty."
      continue
    fi
    read -r -s -p "Confirm ${label}: " s2; echo
    if [[ "${s1}" != "${s2}" ]]; then
      echo "  -> Values did not match. Try again."
      continue
    fi
    printf -v "${var_name}" '%s' "${s1}"
    return 0
  done
}

check_gitignore() {
  local gi="${REPO_ROOT}/.gitignore"
  local missing=()
  for pattern in "provision.env" "pki/issuing-ca/private/*" "pki/root-ca/private/*" "*.key.pem" "*.cred" "venv/" ".venv/"; do
    if [[ ! -f "${gi}" ]] || ! grep -qF -- "${pattern}" "${gi}"; then
      missing+=("${pattern}")
    fi
  done
}