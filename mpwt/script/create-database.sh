#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

INVENTORY_DIR="${INVENTORY_DIR:-${REPO_ROOT}/inventory}"
MERGED_SQL_FILE="${INVENTORY_DIR}/setup_database.sql"
CREATE_DB="${CREATE_DB:-true}"

PKI_INIT="${PKI_INIT:-true}"
PKI_ISSUING_CA_DIR="${PKI_ISSUING_CA_DIR:-${REPO_ROOT}/pki/issuing-ca}"
PKI_DB_DIR="${PKI_ISSUING_CA_DIR}/database"
PKI_DB_OWNER="${PKI_DB_OWNER:-root:www-data}"
PKI_SERIAL_START="${PKI_SERIAL_START:-1000}"

DB_HOST="" DB_PORT="" DB_NAME="" DB_USER="" DB_PASSWORD=""

preflight() {
  for c in grep sed mktemp psql diff; do require_cmd "$c"; done
  [[ "${CREATE_DB}" == "true" ]] && require_cmd createdb
  if [[ "${PKI_INIT}" == "true" ]]; then
    for c in sudo mkdir touch chown chmod; do require_cmd "$c"; done
  fi
  [[ -f "${MERGED_SQL_FILE}" ]] || die "Merged schema not found: ${MERGED_SQL_FILE}"
  log "Preflight checks passed."
}

valid_identifier() { [[ "$1" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; }
valid_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( "$1" >= 1 && "$1" <= 65535 )); }

collect_db_config() {
  echo "==================================================================="
  echo " MPWT Database Provisioning - Requirement Collection"
  echo "==================================================================="
  ensure_input_file_perms
  DB_HOST="$(read_env_value DB_HOST "${INPUT_ENV_FILE}" || true)"
  DB_PORT="$(read_env_value DB_PORT "${INPUT_ENV_FILE}" || true)"
  DB_NAME="$(read_env_value DB_NAME "${INPUT_ENV_FILE}" || true)"
  DB_USER="$(read_env_value DB_USER "${INPUT_ENV_FILE}" || true)"
  DB_PASSWORD="$(read_env_value DB_PASSWORD "${INPUT_ENV_FILE}" || true)"

  [[ -z "${DB_HOST}" ]] && DB_HOST="127.0.0.1"
  [[ -z "${DB_PORT}" ]] && DB_PORT="5432"

  if [[ -z "${DB_NAME}" ]]; then
    read -r -p "Database name [mpwt]: " DB_NAME
    DB_NAME="${DB_NAME:-mpwt}"
  fi
  valid_identifier "${DB_NAME}" || die "DB_NAME '${DB_NAME}' is not a safe identifier."

  if [[ -z "${DB_USER}" ]]; then
    read -r -p "Database user [mpwt]: " DB_USER
    DB_USER="${DB_USER:-mpwt}"
  fi
  valid_identifier "${DB_USER}" || die "DB_USER '${DB_USER}' is not a safe identifier."

  valid_port "${DB_PORT}" || die "DB_PORT '${DB_PORT}' is not a valid port number."

  if [[ -z "${DB_PASSWORD}" ]]; then
    prompt_secret DB_PASSWORD "Database password for ${DB_USER}" false
  fi

  log "Collected DB config: host=${DB_HOST} port=${DB_PORT} db=${DB_NAME} user=${DB_USER} (password redacted)."
}

create_role_and_database() {
  [[ "${CREATE_DB}" == "true" ]] || { log "CREATE_DB=false -- skipping role/database creation."; return 0; }
  require_cmd sudo
  log "Ensuring role '${DB_USER}' exists..."
  sudo -u postgres psql -v ON_ERROR_STOP=1 -v db_user="${DB_USER}" -v db_pass="${DB_PASSWORD}" <<-'EOSQL'
    SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'db_user', :'db_pass')
    WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = :'db_user') \gexec

    SELECT format('ALTER ROLE %I WITH PASSWORD %L', :'db_user', :'db_pass')
    WHERE EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = :'db_user') \gexec
EOSQL
  local exists
  exists="$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname = '${DB_NAME}';" 2>/dev/null || true)"
  if [[ "${exists}" != "1" ]]; then
    log "Creating database '${DB_NAME}' owned by '${DB_USER}'..."
    sudo -u postgres createdb -O "${DB_USER}" "${DB_NAME}"
  else
    log "Database '${DB_NAME}' already exists -- skipping creation."
  fi
}

apply_schema() {
  log "Applying merged schema (${MERGED_SQL_FILE}) to ${DB_NAME}@${DB_HOST}:${DB_PORT} as ${DB_USER}..."
  PGPASSWORD="${DB_PASSWORD}" psql \
    -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" \
    -v ON_ERROR_STOP=1 \
    -f "${MERGED_SQL_FILE}" \
    || die "Applying merged schema failed. Database and role were still created/left in place -- fix the SQL and re-run."
  log "Schema applied successfully."
}

setup_pki_issuing_ca_database() {
  [[ "${PKI_INIT}" == "true" ]] || { log "PKI_INIT=false -- skipping PKI issuing CA database init."; return 0; }
  if [[ ! -d "${PKI_ISSUING_CA_DIR}" ]]; then
    log "WARNING: ${PKI_ISSUING_CA_DIR} does not exist yet. Creating database/ under it anyway."
  fi
  log "Ensuring PKI issuing CA database directory exists: ${PKI_DB_DIR}"
  sudo mkdir -p "${PKI_DB_DIR}"
  if [[ ! -f "${PKI_DB_DIR}/index.txt" ]]; then
    log "Creating empty CA certificate index: ${PKI_DB_DIR}/index.txt"
    sudo touch "${PKI_DB_DIR}/index.txt"
  else
    log "CA index already exists -- leaving as-is: ${PKI_DB_DIR}/index.txt"
  fi
  if [[ ! -f "${PKI_DB_DIR}/serial" ]]; then
    log "Initializing CA serial counter to ${PKI_SERIAL_START}"
    sudo sh -c "echo '${PKI_SERIAL_START}' > '${PKI_DB_DIR}/serial'"
  else
    log "CA serial file already exists -- NOT overwriting: ${PKI_DB_DIR}/serial"
  fi
  log "Locking down ownership/permissions on ${PKI_DB_DIR}..."
  sudo chmod 750 "${PKI_DB_DIR}"
  sudo find "${PKI_DB_DIR}" -maxdepth 1 -type f -exec chmod 640 {} +
  log "PKI issuing CA database ready: ${PKI_DB_DIR}"
}

main() {
  preflight
  collect_db_config
  create_role_and_database
  apply_schema
  setup_pki_issuing_ca_database
  check_gitignore

  echo
  echo "==================================================================="
  echo " Database ready."
  echo "   Host   : ${DB_HOST}:${DB_PORT}"
  echo "   DB     : ${DB_NAME}"
  echo "   User   : ${DB_USER}"
  echo "   Schema : ${MERGED_SQL_FILE}"
  if [[ "${PKI_INIT}" == "true" ]]; then
    echo "   PKI DB : ${PKI_DB_DIR} (index.txt, serial)"
  fi
  echo " Make sure DB_PASSWORD in provision.env matches what was used here"
  echo " before running encrypt-secrets.sh."
  echo "==================================================================="
}

main "$@"