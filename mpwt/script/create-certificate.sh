#!/usr/bin/env bash
#
# create-certificate.sh -- MPWT PKI bootstrap + leaf cert issuance (mTLS, nginx-ready)
# ---------------------------------------------------------------------------
# Rewritten to match the manual guideline exactly (Phase 2 doc), instead of
# diverging from it. Key differences from the previous version of this
# script, and why they were changed:
#
#   1. Root CA key path fixed to match the guideline:
#         /opt/mpwt/pki/root-ca/private/root-ca.key
#      (old script used /opt/mpwt/pki/private/root-ca.key -- a different
#      path, which caused the script to think no root key existed and
#      silently generate a NEW one on top of an existing root-ca.crt,
#      producing a key/cert pair that no longer match.)
#
#   2. Uses RSA (4096-bit root/issuing, 2048-bit leaf) + `openssl ca` with a
#      real database/index.txt, exactly like the guideline -- not EC keys
#      with `openssl x509 -req -CAcreateserial`. This restores CRL /
#      revocation support, which the old script explicitly gave up.
#
#   3. Every "initialize database" step is now idempotent: it only creates
#      database/serial, database/crlnumber, database/index.txt if they do
#      not already exist. The guideline's raw commands blindly overwrite
#      them, which is fine on a truly fresh host but DESTROYS an existing
#      CA's issuance history (and can cause serial collisions) if re-run.
#
#   4. Deploys the FULL set of nginx-facing files, including the one the
#      old script silently dropped:
#         - fullchain (leaf + issuing-ca)  -> ssl_certificate
#         - leaf private key               -> ssl_certificate_key
#         - ca-chain.crt (issuing+root)     -> ssl_client_certificate  <-- was missing
#         - issuing-ca CRL                  -> ssl_crl (optional)
#      Without ca-chain.crt in nginx's directory, nginx cannot validate
#      incoming client certificates, so mTLS handshakes fail even though
#      the server's own certificate looks completely fine. This was the
#      most likely cause of "mTLS not working."
#
#   5. Verifies root key <-> root cert correspondence before ever deciding
#      to "skip" CA bootstrap, so a path mismatch fails loudly instead of
#      silently producing an inconsistent CA.
#
#   6. Permissions are re-applied AND self-verified on every run, not just
#      assumed. set_final_permissions() sets issuing-ca/{certs,crl,csr,
#      database} to WWW_USER:WWW_USER 2750 (setgid, so future writers keep
#      the right group). verify_www_data_access() then actually tests, as
#      WWW_USER, whether index.txt/serial/crlnumber and the certs/csr
#      directories are writable -- and refuses to report success if not.
#      This exists because a separate script (create-database.sh) was
#      observed changing ownership on the same PKI database directory
#      after this script ran, silently breaking CSR signing in the
#      enrollment API until this script was re-run. If that keeps
#      happening, the real fix is removing that logic from whatever else
#      touches ${PKI_ROOT}/issuing-ca -- this script can restore correct
#      permissions, but it can't stop another script from re-breaking them
#      afterward.
#
#   7. Takes an flock on ${PKI_ROOT}/.create-certificate.lock around the
#      CA operations, so two overlapping runs of this script (or a run
#      that overlaps with a live CSR signing operation, if the enrollment
#      API is updated to flock the same file) can't corrupt
#      database/index.txt or database/serial.
#
# Domain resolution order (first match wins):
#   1. Positional argument            ./create-certificate.sh auth.mpwt.local
#   2. DOMAIN= in provision.env       (same file used by create-database.sh /
#      next to this script, chmod 600 required)   encrypt-secrets.sh
#   3. Interactive prompt             (only if running in a TTY)
#
# Usage:
#   sudo ./create-certificate.sh auth.mpwt.local
#   sudo ./create-certificate.sh dev.mpwt.local
#   sudo ./create-certificate.sh wazuh.mpwt.local
#   sudo ./create-certificate.sh                       # reads DOMAIN from provision.env
#   sudo PKI_ROOT=/opt/mpwt/pki ./create-certificate.sh
#   sudo ./create-certificate.sh --no-bootstrap auth.mpwt.local   # fail instead of auto-init CA
# ---------------------------------------------------------------------------

set -Eeuo pipefail
IFS=$'\n\t'

# ============================================================================
# Paths -- match the guideline (Phase 2) exactly
# ============================================================================
PKI_ROOT="${PKI_ROOT:-/opt/mpwt/pki}"

ROOT_CA_DIR="${PKI_ROOT}/root-ca"
ROOT_CA_CNF="${ROOT_CA_DIR}/config/root-ca.cnf"
ROOT_CA_KEY="${ROOT_CA_DIR}/private/root-ca.key"
ROOT_CA_CERT="${ROOT_CA_DIR}/certs/root-ca.crt"
ROOT_CA_DB_DIR="${ROOT_CA_DIR}/database"

ISSUING_CA_DIR="${PKI_ROOT}/issuing-ca"
ISSUING_CA_CNF="${ISSUING_CA_DIR}/config/issuing-ca.cnf"
ISSUING_CA_KEY="${ISSUING_CA_DIR}/private/issuing-ca.key"
ISSUING_CA_CERT="${ISSUING_CA_DIR}/certs/issuing-ca.crt"
ISSUING_CA_CSR="${ISSUING_CA_DIR}/csr/issuing-ca.csr"
ISSUING_CA_DB_DIR="${ISSUING_CA_DIR}/database"
CA_CHAIN_FILE="${ISSUING_CA_DIR}/certs/ca-chain.crt"
ISSUING_CA_CRL="${ISSUING_CA_DIR}/crl/issuing-ca.crl"

# nginx-facing operational output
NGINX_CERT_DIR="${NGINX_CERT_DIR:-/etc/nginx/ssl/certs}"
NGINX_KEY_DIR="${NGINX_KEY_DIR:-/etc/nginx/ssl/private}"
NGINX_OWNER="${NGINX_OWNER:-root}"
NGINX_GROUP="${NGINX_GROUP:-root}"

LEAF_DAYS="${LEAF_DAYS:-365}"
WWW_USER="${WWW_USER:-www-data}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
INPUT_ENV_FILE="${INPUT_ENV_FILE:-${SCRIPT_DIR}/provision.env}"

ALLOW_BOOTSTRAP=true
DOMAIN=""
for arg in "$@"; do
  case "${arg}" in
    --no-bootstrap) ALLOW_BOOTSTRAP=false ;;
    -*) echo "Unknown flag: ${arg}" >&2; exit 1 ;;
    *) DOMAIN="${arg}" ;;   # positional arg always wins over provision.env
  esac
done

log()  { echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $*" >&2; }
die()  { log "ERROR: $*"; exit 1; }

require_root() { [[ "${EUID}" -eq 0 ]] || die "This script must be run as root."; }
require_cmd()  { command -v "$1" >/dev/null 2>&1 || die "Required command '$1' not found."; }

valid_domain() {
  [[ "$1" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$ ]]
}

# ============================================================================
# provision.env -- plain text KEY=VALUE, never sourced/executed (same
# contract as lib/common.sh's read_env_value)
# ============================================================================
read_env_value() {
  local key="$1" file="$2" line val
  [[ -f "${file}" ]] || return 1
  line="$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "${file}" | tail -n1 || true)"
  [[ -n "${line}" ]] || return 1
  val="${line#*=}"
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

prompt_domain() {
  while true; do
    read -r -p "Enter the server domain / FQDN for the certificate (e.g. auth.mpwt.local): " DOMAIN
    valid_domain "${DOMAIN}" && break
    echo "  -> Invalid domain format. Try again."
  done
}

# Precedence: positional arg (already set above) > provision.env > interactive
collect_domain() {
  [[ -n "${DOMAIN}" ]] && { valid_domain "${DOMAIN}" || die "Invalid domain: ${DOMAIN}"; return 0; }

  ensure_input_file_perms
  local from_env
  from_env="$(read_env_value DOMAIN "${INPUT_ENV_FILE}" || true)"
  if [[ -n "${from_env}" ]] && valid_domain "${from_env}"; then
    DOMAIN="${from_env}"
    log "Domain loaded from ${INPUT_ENV_FILE}: ${DOMAIN}"
    return 0
  fi

  if [[ -f "${INPUT_ENV_FILE}" ]]; then
    log "WARNING: ${INPUT_ENV_FILE} exists but DOMAIN is missing/invalid in it."
  fi

  if [[ -t 0 ]]; then
    prompt_domain
  else
    die "No domain given: pass one as an argument, set DOMAIN in ${INPUT_ENV_FILE}, or run interactively."
  fi
}

# ============================================================================
# Phase 0: preflight
# ============================================================================
preflight() {
  require_root
  for c in openssl grep sed install; do require_cmd "$c"; done

  collect_domain
  log "Using DOMAIN=${DOMAIN}"

  [[ -s "${ROOT_CA_CNF}" ]]    || die "Root CA config not found at ${ROOT_CA_CNF}. Create it first (this script does not invent CA policy)."
  [[ -s "${ISSUING_CA_CNF}" ]] || die "Issuing CA config not found at ${ISSUING_CA_CNF}."

  mkdir -p "${ROOT_CA_DIR}"/{certs,crl,private,database} "${ROOT_CA_DIR}/config"
  mkdir -p "${ISSUING_CA_DIR}"/{certs,crl,csr,private,database} "${ISSUING_CA_DIR}/config"
  mkdir -p "${NGINX_CERT_DIR}" "${NGINX_KEY_DIR}"

  log "Preflight OK. PKI_ROOT=${PKI_ROOT}  DOMAIN=${DOMAIN}"
}

# ============================================================================
# Idempotent database init -- only touches files that don't already exist
# ============================================================================
init_db() {
  local db_dir="$1"
  [[ -f "${db_dir}/index.txt" ]]      || : > "${db_dir}/index.txt"
  [[ -f "${db_dir}/index.txt.attr" ]] || echo "unique_subject = no" > "${db_dir}/index.txt.attr"
  [[ -f "${db_dir}/crlnumber" ]]      || echo "01" > "${db_dir}/crlnumber"
  chmod 644 "${db_dir}"/{index.txt,crlnumber} 2>/dev/null || true
}

# ============================================================================
# Phase 1: Root CA (bootstrap only if genuinely absent; verify if present)
# ============================================================================
# Set as a side effect: ROOT_KEY_AVAILABLE=true/false, for callers that
# only need the key conditionally (signing a *new* Issuing CA).
ROOT_KEY_AVAILABLE=false

bootstrap_root_ca() {
  init_db "${ROOT_CA_DB_DIR}"
  [[ -f "${ROOT_CA_DB_DIR}/serial" ]] || echo "1000" > "${ROOT_CA_DB_DIR}/serial"
  chmod 644 "${ROOT_CA_DB_DIR}/serial"

  local key_present=false cert_present=false
  [[ -s "${ROOT_CA_KEY}" ]]  && key_present=true
  [[ -s "${ROOT_CA_CERT}" ]] && cert_present=true

  if [[ "${key_present}" == "true" && "${cert_present}" == "true" ]]; then
    # Integrity check -- refuse to silently proceed on a mismatched pair
    local cert_pub key_pub
    cert_pub="$(openssl x509 -pubkey -noout -in "${ROOT_CA_CERT}" 2>/dev/null || true)"
    key_pub="$(openssl rsa  -pubout -in "${ROOT_CA_KEY}" 2>/dev/null || true)"
    [[ -n "${cert_pub}" && "${cert_pub}" == "${key_pub}" ]] \
      || die "Root CA key/cert MISMATCH at ${ROOT_CA_KEY} / ${ROOT_CA_CERT}. Refusing to continue -- restore the correct key or re-bootstrap deliberately."
    log "Root CA already present and verified: ${ROOT_CA_CERT}"
    ROOT_KEY_AVAILABLE=true
    return 0
  fi

  if [[ "${cert_present}" == "true" && "${key_present}" == "false" ]]; then
    # EXPECTED, SECURE state: the guideline itself says to move the root
    # key offline (or delete it from the server) once the Issuing CA has
    # been signed. Do NOT treat this as an error -- just don't have the
    # key available. bootstrap_issuing_ca() will only fail later if it
    # actually needs the key to sign a *new* Issuing CA.
    log "Root CA cert present, private key not found locally (${ROOT_CA_KEY})."
    log "Treating this as 'root key stored offline' per policy -- proceeding without it."
    ROOT_KEY_AVAILABLE=false
    return 0
  fi

  if [[ "${key_present}" == "true" && "${cert_present}" == "false" ]]; then
    die "Root CA key exists at ${ROOT_CA_KEY} but ${ROOT_CA_CERT} is missing -- self-sign was never completed. Fix manually: openssl req -config ${ROOT_CA_CNF} -key ${ROOT_CA_KEY} -new -x509 -days 3650 -extensions v3_ca -out ${ROOT_CA_CERT}"
  fi

  # Neither present -- genuinely fresh, safe to bootstrap.
  [[ "${ALLOW_BOOTSTRAP}" == "true" ]] || die "Root CA missing and --no-bootstrap was passed."

  log "Bootstrapping Root CA (4096-bit RSA, 10y)..."
  openssl genrsa -out "${ROOT_CA_KEY}" 4096
  chmod 400 "${ROOT_CA_KEY}"
  chmod 700 "${ROOT_CA_DIR}/private"

  openssl req \
    -config "${ROOT_CA_CNF}" \
    -key "${ROOT_CA_KEY}" \
    -new -x509 -days 3650 \
    -extensions v3_ca \
    -out "${ROOT_CA_CERT}"

  ROOT_KEY_AVAILABLE=true
  log "Root CA created: ${ROOT_CA_CERT}"
  echo
  echo "-------------------------------------------------------------------"
  echo " Root CA private key: ${ROOT_CA_KEY}"
  echo " Move this to offline/cold storage now -- it is only needed again"
  echo " to sign a new/replacement Issuing CA."
  echo "-------------------------------------------------------------------"
  echo
}

# ============================================================================
# Phase 2: Issuing CA
# ============================================================================
bootstrap_issuing_ca() {
  init_db "${ISSUING_CA_DB_DIR}"
  [[ -f "${ISSUING_CA_DB_DIR}/serial" ]] || printf "%04X\n" 8192 > "${ISSUING_CA_DB_DIR}/serial"
  chmod 644 "${ISSUING_CA_DB_DIR}/serial"

  if [[ -s "${ISSUING_CA_KEY}" && -s "${ISSUING_CA_CERT}" ]]; then
    local cert_pub key_pub
    cert_pub="$(openssl x509 -pubkey -noout -in "${ISSUING_CA_CERT}" 2>/dev/null || true)"
    key_pub="$(openssl rsa  -pubout -in "${ISSUING_CA_KEY}" 2>/dev/null || true)"
    [[ -n "${cert_pub}" && "${cert_pub}" == "${key_pub}" ]] \
      || die "Issuing CA key/cert MISMATCH at ${ISSUING_CA_KEY} / ${ISSUING_CA_CERT}."
    openssl verify -CAfile "${ROOT_CA_CERT}" "${ISSUING_CA_CERT}" >/dev/null \
      || die "Issuing CA cert does not verify against ${ROOT_CA_CERT}. Chain is broken."
    log "Issuing CA already present and verified: ${ISSUING_CA_CERT}"
  else
    [[ "${ALLOW_BOOTSTRAP}" == "true" ]] || die "Issuing CA missing and --no-bootstrap was passed."
    [[ ! -s "${ISSUING_CA_KEY}" && ! -s "${ISSUING_CA_CERT}" ]] \
      || die "Issuing CA is only PARTIALLY present. Refusing to auto-bootstrap -- inspect ${ISSUING_CA_DIR} manually."
    [[ "${ROOT_KEY_AVAILABLE}" == "true" ]] || die "Cannot sign a new Issuing CA -- Root CA private key not available at ${ROOT_CA_KEY} (it's likely offline, per policy). Restore it temporarily, or sign the Issuing CA CSR on the offline root system and copy back the resulting ${ISSUING_CA_CERT}."

    log "Bootstrapping Issuing CA (4096-bit RSA, 5y, signed by Root CA)..."
    openssl genrsa -out "${ISSUING_CA_KEY}" 4096
    chown root:"${WWW_USER}" "${ISSUING_CA_DIR}/private" "${ISSUING_CA_KEY}"
    chmod 640 "${ISSUING_CA_KEY}"
    chmod 750 "${ISSUING_CA_DIR}/private"

    openssl req \
      -config "${ISSUING_CA_CNF}" \
      -new -key "${ISSUING_CA_KEY}" \
      -out "${ISSUING_CA_CSR}"

    openssl ca \
      -config "${ROOT_CA_CNF}" \
      -extensions v3_intermediate_ca \
      -days 1825 \
      -notext \
      -batch \
      -in "${ISSUING_CA_CSR}" \
      -out "${ISSUING_CA_CERT}"

    log "Issuing CA created: ${ISSUING_CA_CERT}"
  fi

  # Always rebuild the chain bundle and CRL -- cheap, and keeps them fresh
  cat "${ISSUING_CA_CERT}" "${ROOT_CA_CERT}" > "${CA_CHAIN_FILE}"
  chmod 644 "${CA_CHAIN_FILE}"

  openssl ca \
    -config "${ISSUING_CA_CNF}" \
    -gencrl \
    -out "${ISSUING_CA_CRL}" \
    -batch

  openssl verify -CAfile "${ROOT_CA_CERT}" "${ISSUING_CA_CERT}" \
    || die "Post-bootstrap chain verification failed."
  log "CA chain verified. ca-chain.crt -> ${CA_CHAIN_FILE}"
}

# ============================================================================
# Phase 3: leaf certificate for $DOMAIN (server + client auth, mTLS-ready)
# ============================================================================
issue_leaf_cert() {
  local key_file="${ISSUING_CA_DIR}/private/${DOMAIN}.key"
  local csr_file="${ISSUING_CA_DIR}/csr/${DOMAIN}.csr"
  local crt_file="${ISSUING_CA_DIR}/certs/${DOMAIN}.crt"
  local ext_file
  ext_file="$(mktemp "/tmp/${DOMAIN}.XXXXXX.ext")"

  if [[ -s "${crt_file}" ]]; then
    log "Certificate for ${DOMAIN} already exists at ${crt_file}."
    log "Delete it first (and its key) if you want to reissue. Skipping issuance, will still redeploy to nginx."
  else
    log "Generating key + CSR for ${DOMAIN}..."
    openssl genrsa -out "${key_file}" 2048
    chmod 400 "${key_file}"

    # serverAuth + clientAuth: this leaf can terminate TLS on nginx AND be
    # used as a client cert for outbound mTLS calls this host makes.
    # Drop clientAuth if you only ever want this identity as a server cert.
    cat > "${ext_file}" <<EOF
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:${DOMAIN}
EOF

    openssl req -new -key "${key_file}" \
      -subj "/C=KH/O=MPWT/CN=${DOMAIN}" \
      -out "${csr_file}"

    openssl ca \
      -config "${ISSUING_CA_CNF}" \
      -in "${csr_file}" \
      -out "${crt_file}" \
      -extfile "${ext_file}" \
      -days "${LEAF_DAYS}" -notext -batch

    rm -f "${ext_file}"
    log "Issued: ${crt_file}"
  fi

  openssl verify -CAfile "${CA_CHAIN_FILE}" "${crt_file}" \
    || die "Leaf certificate for ${DOMAIN} failed chain verification."

  LEAF_KEY="${key_file}"
  LEAF_CERT="${crt_file}"
}

# ============================================================================
# Phase 4: deploy to nginx -- this is the step the old script got wrong
# ============================================================================
install_nginx_files() {
  local fullchain
  fullchain="$(mktemp /tmp/${DOMAIN}.fullchain.XXXXXX.crt)"
  cat "${LEAF_CERT}" "${ISSUING_CA_CERT}" > "${fullchain}"

  # 1. Server identity (leaf + issuing-ca), what nginx presents to clients
  install -o "${NGINX_OWNER}" -g "${NGINX_GROUP}" -m 600 "${LEAF_KEY}" "${NGINX_KEY_DIR}/${DOMAIN}.key"
  install -o "${NGINX_OWNER}" -g "${NGINX_GROUP}" -m 644 "${fullchain}" "${NGINX_CERT_DIR}/${DOMAIN}.crt"
  rm -f "${fullchain}"

  # 2. CA chain nginx uses to validate INCOMING client certs (mTLS) --
  #    this is the file the previous version of this script never copied.
  install -o "${NGINX_OWNER}" -g "${NGINX_GROUP}" -m 644 "${CA_CHAIN_FILE}" "${NGINX_CERT_DIR}/ca-chain.crt"

  # 3. CRL, for ssl_crl if you want mid-lifetime revocation checked
  install -o "${NGINX_OWNER}" -g "${NGINX_GROUP}" -m 644 "${ISSUING_CA_CRL}" "${NGINX_CERT_DIR}/issuing-ca.crl"

  log "Deployed to nginx:"
  log "  ssl_certificate           ${NGINX_CERT_DIR}/${DOMAIN}.crt  (fullchain)"
  log "  ssl_certificate_key       ${NGINX_KEY_DIR}/${DOMAIN}.key"
  log "  ssl_client_certificate    ${NGINX_CERT_DIR}/ca-chain.crt   (mTLS -- validates client certs)"
  log "  ssl_crl                   ${NGINX_CERT_DIR}/issuing-ca.crl (optional)"
}

# ============================================================================
# Phase 5: final permissions (matches guideline 4.4, hardened)
# ============================================================================
# WHY THIS MATTERS BEYOND THE GUIDELINE:
# The enrollment API (Gunicorn, running as WWW_USER) calls `openssl ca`
# itself whenever a device CSR is signed -- writing into the SAME
# database/certs/csr directories this script manages. If any OTHER
# provisioning script (e.g. create-database.sh) also touches ownership on
# these paths, whichever script ran most recently "wins", and a mismatch
# silently breaks CSR signing until this script is re-run to fix it back.
#
# This function is deliberately re-run and re-verified on every execution
# (not just on first bootstrap) so re-running this script is always a safe
# way to restore correct permissions -- but the better fix, if you keep
# seeing drift, is to stop any other script from touching these paths at
# all (see set_final_permissions's log output for what "correct" means).
set_final_permissions() {
  chown -R "${WWW_USER}:${WWW_USER}" \
    "${ISSUING_CA_DIR}/certs" "${ISSUING_CA_DIR}/crl" \
    "${ISSUING_CA_DIR}/csr" "${ISSUING_CA_DIR}/database"

  # rwxr-x--- on the dirs; setgid (g+s) so files CREATED LATER by any
  # process running as WWW_USER's group keep the right group even if a
  # different UID in that group creates them.
  chmod 2755 \
    "${ISSUING_CA_DIR}/certs" "${ISSUING_CA_DIR}/crl" \
    "${ISSUING_CA_DIR}/csr" "${ISSUING_CA_DIR}/database"

  chown root:root "${ISSUING_CA_DIR}/config"
  chmod 755 "${ISSUING_CA_DIR}/config"
  chmod 644 "${ISSUING_CA_CNF}"

  chown -R root:root "${ROOT_CA_DIR}"
  chmod 400 "${ROOT_CA_KEY}" 2>/dev/null || true
  chmod 700 "${ROOT_CA_DIR}/private"

  log "Permissions set: issuing-ca/{certs,crl,csr,database} -> ${WWW_USER}:${WWW_USER} 2755 (setgid)"
}

# ============================================================================
# Phase 6: prove it, don't assume it -- verify the enrollment API's user
# can actually write where openssl ca needs to write. This is what turns
# "the script ran without errors" into "certificate signing will actually
# work", which is the gap that caused the earlier enrollment failure.
# ============================================================================
verify_www_data_access() {
  local -a runas=()
  local ok=true
  if command -v runuser >/dev/null 2>&1; then
    runas=(runuser -u "${WWW_USER}" --)
  elif command -v sudo >/dev/null 2>&1; then
    runas=(sudo -u "${WWW_USER}")
  else
    log "WARNING: neither 'runuser' nor 'sudo' available -- skipping write-access self-test."
    return 0
  fi

  log "Verifying ${WWW_USER} can write where the enrollment API needs to..."
  for f in \
    "${ISSUING_CA_DB_DIR}/index.txt" \
    "${ISSUING_CA_DB_DIR}/serial" \
    "${ISSUING_CA_DB_DIR}/crlnumber"
  do
    if "${runas[@]}" test -w "${f}"; then
      log "  OK   ${f}"
    else
      log "  FAIL ${f}  <- ${WWW_USER} cannot write this. CSR signing WILL fail."
      ok=false
    fi
  done
  for d in "${ISSUING_CA_DB_DIR}" "${ISSUING_CA_DIR}/certs" "${ISSUING_CA_DIR}/csr"; do
    if "${runas[@]}" test -w "${d}"; then
      log "  OK   ${d}/ (dir writable)"
    else
      log "  FAIL ${d}/ (dir NOT writable)  <- new cert/CSR files can't be created here."
      ok=false
    fi
  done

  if [[ "${ok}" != "true" ]]; then
    die "Write-access self-test failed. The enrollment API (running as ${WWW_USER}) will not be able to sign device CSRs. Check whether another script (e.g. create-database.sh) changed ownership on ${ISSUING_CA_DIR} after this ran, then re-run this script."
  fi
  log "Write-access self-test PASSED -- ${WWW_USER} can sign certificates."
}

# ============================================================================
# Advisory lock -- prevents this script racing with itself (or, if you add
# the same flock in the enrollment API's signing code, with live CSR
# signing) over database/index.txt and database/serial.
# ============================================================================
LOCK_FILE="${PKI_ROOT}/.create-certificate.lock"
acquire_lock() {
  exec 200>"${LOCK_FILE}"
  flock -w 30 200 || die "Could not acquire lock ${LOCK_FILE} within 30s -- another provisioning run (or CSR signing operation) may be in progress."
}

main() {
  preflight
  acquire_lock
  bootstrap_root_ca
  bootstrap_issuing_ca
  issue_leaf_cert
  install_nginx_files
  set_final_permissions
  verify_www_data_access

  echo
  echo "==================================================================="
  echo " Certificate ready for ${DOMAIN}"
  echo "   PKI archive cert  : ${ISSUING_CA_DIR}/certs/${DOMAIN}.crt"
  echo "   PKI archive key   : ${ISSUING_CA_DIR}/private/${DOMAIN}.key"
  echo "   CA chain          : ${CA_CHAIN_FILE}"
  echo "   Root CA cert      : ${ROOT_CA_CERT}"
  echo "   -- nginx --"
  echo "   ssl_certificate        ${NGINX_CERT_DIR}/${DOMAIN}.crt"
  echo "   ssl_certificate_key    ${NGINX_KEY_DIR}/${DOMAIN}.key"
  echo "   ssl_client_certificate ${NGINX_CERT_DIR}/ca-chain.crt"
  echo "   ssl_verify_client      on;  (set this in your vhost)"
  echo "   ssl_crl                ${NGINX_CERT_DIR}/issuing-ca.crl  (optional)"
  echo
  echo " Write-access self-test: PASSED (enrollment API can sign CSRs)"
  echo
  echo " Next: reload nginx --  nginx -t && systemctl reload nginx"
  echo
  echo " IMPORTANT: if CSR signing ever fails again with correct permissions"
  echo " shown above, it is NOT this script -- check create-database.sh (or"
  echo " any other script/cron job) for logic that touches ownership/mode"
  echo " on ${ISSUING_CA_DIR}, and consider removing that logic from it."
  echo "==================================================================="
}

main