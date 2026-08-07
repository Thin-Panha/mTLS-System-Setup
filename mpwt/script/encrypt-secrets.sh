#!/usr/bin/env bash
#
# encrypt-secrets.sh
# ---------------------------------------------------------------------------
# Encrypts application secrets (Telegram bot token, API key, Flask secret,
# policy HMAC key, DB password) into systemd-creds .cred files under
# /etc/mpwt/creds. Does NOT touch the TLS certificate -- see
# create-certificate.sh / cre.sh for that.
#
# Reads values from provision.env; prompts (hidden input) for anything
# missing. Nothing sensitive is ever printed or logged in plaintext.
#
# Requires systemd >= 250 (systemd-creds).
#
# Usage:
#   sudo ./encrypt-secrets.sh
#   sudo REPO_ROOT=/opt/mpwt ./encrypt-secrets.sh
# ---------------------------------------------------------------------------

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# Group that the mpwt-admin CLI's setgid helper (mpwt-admin-keyfetch) runs
# as, so it can read the CLI's own copy of the API key without being root.
CLI_ADMIN_GROUP="${CLI_ADMIN_GROUP:-mpwt-admin}"

TELEGRAM_BOT_TOKEN=""
MPWT_API_KEY=""
SECRET_KEY=""
POLICY_HMAC_KEY=""
DB_PASSWORD=""

preflight() {
  require_root
  for c in openssl grep sed mktemp shred install id systemd-creds getent groupadd; do
    require_cmd "$c"
  done

  local sd_ver
  sd_ver="$(systemctl --version | head -n1 | awk '{print $2}')"
  if [[ -n "${sd_ver}" && "${sd_ver}" -lt 250 ]]; then
    die "systemd ${sd_ver} detected; systemd-creds requires systemd >= 250."
  fi

  require_service_user
  ensure_cli_admin_group

  if command -v systemd-cryptenroll >/dev/null 2>&1 && systemd-cryptenroll --tpm2-device=list >/dev/null 2>&1; then
    log "TPM 2.0 detected -- credentials will be hardware-bound to this machine."
  else
    log "No TPM detected -- credentials will use the host-only key at /var/lib/systemd/credential.secret."
  fi

  log "Preflight checks passed."
}

# The mpwt-admin CLI's setgid helper needs this group to exist before we can
# chown the CLI credential to it. Don't require an operator to have created
# it out-of-band first -- create it here, idempotently, if missing.
ensure_cli_admin_group() {
  if getent group "${CLI_ADMIN_GROUP}" >/dev/null 2>&1; then
    log "Group '${CLI_ADMIN_GROUP}' already exists."
  else
    groupadd --system "${CLI_ADMIN_GROUP}"
    log "Created system group '${CLI_ADMIN_GROUP}' (add CLI operators to it with: usermod -aG ${CLI_ADMIN_GROUP} <user>)."
  fi
}

collect_secrets() {
  echo "==================================================================="
  echo " MPWT Secret Encryption - Requirement Collection"
  echo " Input is hidden for secrets. Nothing here is logged or echoed back."
  echo "==================================================================="

  ensure_input_file_perms
  TELEGRAM_BOT_TOKEN="$(read_env_value TELEGRAM_BOT_TOKEN "${INPUT_ENV_FILE}" || true)"
  MPWT_API_KEY="$(read_env_value MPWT_API_KEY "${INPUT_ENV_FILE}" || true)"
  SECRET_KEY="$(read_env_value SECRET_KEY "${INPUT_ENV_FILE}" || true)"
  POLICY_HMAC_KEY="$(read_env_value POLICY_HMAC_KEY "${INPUT_ENV_FILE}" || true)"
  DB_PASSWORD="$(read_env_value DB_PASSWORD "${INPUT_ENV_FILE}" || true)"

  if [[ -n "${TELEGRAM_BOT_TOKEN}" ]] && valid_telegram_token "${TELEGRAM_BOT_TOKEN}"; then
    echo "Telegram bot token loaded from ${INPUT_ENV_FILE} (hidden)."
  else
    prompt_telegram_token
  fi

  [[ -z "${MPWT_API_KEY}" ]]    && prompt_secret MPWT_API_KEY "Enrollment API key (shared by bot + API + CLI)" true 24
  [[ -z "${SECRET_KEY}" ]]      && prompt_secret SECRET_KEY "Flask secret key (enrollment API)" true 64
  [[ -z "${POLICY_HMAC_KEY}" ]] && prompt_secret POLICY_HMAC_KEY "Policy HMAC key" true 32
  [[ -z "${DB_PASSWORD}" ]]     && prompt_secret DB_PASSWORD "Database password" false

  log "Collected secrets (values redacted)."
}

prepare_creds_dir() {
  mkdir -p "${CREDS_DIR}"
  chown root:root "${CREDS_DIR}"
  chmod 700 "${CREDS_DIR}"
  log "Credentials directory ready: ${CREDS_DIR} (root:root, 700)"
}

# encrypt_cred <credential-name> <output-filename> <plaintext-value> [owner:group] [mode]
#
# owner:group / mode default to root:root / 600, correct for creds consumed
# only via systemd's LoadCredentialEncrypted= (which reads as root before
# dropping privileges). Pass an explicit owner:group/mode for creds that a
# non-root CLI helper needs to read directly via group membership instead
# (e.g. root:mpwt-admin / 640) -- 600 root:root would make those
# undecryptable by anyone but root, no matter how the CLI helper is set up.
encrypt_cred() {
  local cred_name="$1" out_file="$2" value="$3"
  local owner_group="${4:-root:root}"
  local mode="${5:-600}"
  local out_path="${CREDS_DIR}/${out_file}"

  [[ -n "${value}" ]] || die "Refusing to encrypt an empty value for credential '${cred_name}'."

  printf '%s' "${value}" | systemd-creds encrypt --name="${cred_name}" - "${out_path}" \
    || die "systemd-creds encrypt failed for '${cred_name}'."

  chmod "${mode}" "${out_path}"
  chown "${owner_group}" "${out_path}"
  log "Encrypted credential '${cred_name}' -> ${out_path} (${mode}, ${owner_group})"
}

# Verify a credential decrypts correctly WITHOUT printing the plaintext.
verify_cred() {
  local cred_name="$1" out_file="$2"
  local out_path="${CREDS_DIR}/${out_file}"
  if systemd-creds decrypt --name="${cred_name}" "${out_path}" - >/dev/null 2>&1; then
    log "Verified credential '${cred_name}' (${out_file}) decrypts OK."
  else
    die "Verification FAILED for credential '${cred_name}' (${out_file}) -- name mismatch or corrupt file."
  fi
}

encrypt_all_secrets() {
  prepare_creds_dir

  encrypt_cred "telegram_token"  "telegram_token.cred"     "${TELEGRAM_BOT_TOKEN}"
  encrypt_cred "mpwt_api_key_bot"    "mpwt_api_key_bot.cred"    "${MPWT_API_KEY}"
  encrypt_cred "mpwt_api_key_enroll"    "mpwt_api_key_enroll.cred" "${MPWT_API_KEY}"

  # CLI credential -- deliberately different owner/mode from the others.
  # mpwt-admin-keyfetch is a setgid-mpwt-admin helper (not root, not run
  # under systemd's LoadCredentialEncrypted=), so it reads this file
  # directly as a member of the mpwt-admin group. root:root/600 would make
  # it unreadable regardless of the helper's own permissions.
  encrypt_cred "mpwt_api_key_cli"    "mpwt_api_key_cli.cred"    "${MPWT_API_KEY}" "root:${CLI_ADMIN_GROUP}" 640

  encrypt_cred "secret_key"      "secret_key.cred"          "${SECRET_KEY}"
  encrypt_cred "policy_hmac_key" "policy_hmac_key.cred"     "${POLICY_HMAC_KEY}"
  encrypt_cred "db_password"     "db_password.cred"         "${DB_PASSWORD}"

  verify_cred "telegram_token"  "telegram_token.cred"
  verify_cred "mpwt_api_key_bot"    "mpwt_api_key_bot.cred"
  verify_cred "mpwt_api_key_enroll"    "mpwt_api_key_enroll.cred"
  verify_cred "mpwt_api_key_cli"    "mpwt_api_key_cli.cred"
  verify_cred "secret_key"      "secret_key.cred"
  verify_cred "policy_hmac_key" "policy_hmac_key.cred"
  verify_cred "db_password"     "db_password.cred"
}

main() {
  preflight
  collect_secrets
  encrypt_all_secrets
  check_gitignore

  echo
  echo "==================================================================="
  echo " Secrets encrypted via systemd-creds."
  echo "   Creds: ${CREDS_DIR}/*.cred"
  echo "     - telegram_token.cred, mpwt_api_key_bot.cred,"
  echo "       mpwt_api_key_enroll.cred, secret_key.cred,"
  echo "       policy_hmac_key.cred, db_password.cred  -> root:root, 600"
  echo "     - mpwt_api_key_cli.cred                    -> root:${CLI_ADMIN_GROUP}, 640"
  echo "==================================================================="
}

main "$@"