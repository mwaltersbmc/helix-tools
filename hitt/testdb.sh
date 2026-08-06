#!/usr/bin/env bash
#
# Standalone Helix IS database connectivity check — same logic as checkISDBSettings in hitt.sh.
#
# Requires dbjars.tgz (JISQL + JDBC drivers) in the working directory or next to this script:
#   curl -skO https://raw.githubusercontent.com/mwaltersbmc/helix-tools/main/hitt/dbjars.tgz
#
# Usage:
#   bash testdb.sh --host db.example.com --port 1433 --type mssql --user aruser --password 'secret' --dbname ARSystem
#   bash testdb.sh --config mydb.env
#
# Environment variables (alternative to flags): IS_DATABASE_HOST_NAME, IS_DB_PORT, IS_DB_TYPE,
#   IS_AR_DB_USER, IS_AR_DB_PASSWORD, IS_AR_DB_NAME, IS_ORACLE_SERVICE_NAME, IS_DB_VERSION,
#   IS_DATABASE_RESTORE, IS_DATABASE_ADMIN_USER, IS_DATABASE_ADMIN_PASSWORD
#

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

: "${JAVA_BIN:=java}"
: "${TAR_BIN:=tar}"
: "${VERBOSITY:=1}"
: "${QUIET:=0}"
: "${DBJARS_TGZ:=}"
: "${IS_DATABASE_RESTORE:=false}"

FAIL=0
WARN=0

logMessage() {
  local MSG_LEVEL=0
  [[ -n "${2:-}" ]] && MSG_LEVEL=${2}
  [[ ${MSG_LEVEL} -le ${VERBOSITY} ]] && [[ "${QUIET}" == "0" ]] && echo -e "\t${1}"
}

logError() {
  echo -e "ERROR (${1}) - ${2}" >&2
  ((FAIL++)) || true
  [[ "${3:-}" == "1" ]] && exit 1
}

logWarning() {
  echo -e "WARNING (${1}) - ${2}" >&2
  ((WARN++)) || true
}

logStatus() {
  [[ "${QUIET}" == "0" ]] && echo -e "\n${1}"
}

testNetConnection() {
  (echo > /dev/tcp/"${1}"/"${2}") >/dev/null 2>&1
}

buildJISQLcmd() {
  case ${IS_DB_TYPE} in
    mssql)
      JISQLJAR=sqljdbc4.jar
      JISQLURL=jdbc:sqlserver://${IS_DATABASE_HOST_NAME}:${IS_DB_PORT}
      JISQLDRIVER=mssql
      ;;
    oracle)
      JISQLJAR=ojdbc8.jar
      JISQLURL=jdbc:oracle:thin:@//${IS_DATABASE_HOST_NAME}:${IS_DB_PORT}/${IS_ORACLE_SERVICE_NAME}
      JISQLDRIVER=oraclethin
      ;;
    postgres)
      JISQLJAR=postgresql-42.2.8.jar
      JISQLURL=jdbc:postgresql://${IS_DATABASE_HOST_NAME}:${IS_DB_PORT}/${JISQL_DB_NAME}
      JISQLDRIVER=postgresql
      ;;
    *)
      logError "999" "Unsupported IS_DB_TYPE '${IS_DB_TYPE}' — use mssql, oracle, or postgres." 1
      ;;
  esac
  JISQLCMD="${JAVA_BIN} -cp ./jisql.jar:./${JISQLJAR} com.xigole.util.sql.Jisql -user ${JISQL_USERNAME} -password ${JISQL_PASSWORD} -driver ${JISQLDRIVER} -cstring ${JISQLURL} -noheader -query"
}

# From hitt.sh checkISDBSettings
checkISDBSettings() {
  if ! testNetConnection "${IS_DATABASE_HOST_NAME}" "${IS_DB_PORT}"; then
    logWarning "027" "IS DB server '${IS_DATABASE_HOST_NAME}' is not reachable on port '${IS_DB_PORT}' - this is expected if there is no connectivity from this system - skipping DB checks."
    SKIP_DB_CHECKS=1
    return
  else
    logMessage "IS DB server '${IS_DATABASE_HOST_NAME}' is reachable on port '${IS_DB_PORT}'." 1
  fi
  if [ -z "${IS_AR_DB_USER}" ] || [ -z "${IS_AR_DB_PASSWORD}" ]; then
    logError "246" "AR_DB_USER and/or AR_DB_PASSWORD are blank - skipping checks."
    SKIP_AR_DB_CHECKS=1
  fi
  JISQL_USERNAME="${IS_AR_DB_USER}"
  JISQL_PASSWORD="${IS_AR_DB_PASSWORD}"
  JISQL_DB_NAME="${IS_AR_DB_NAME}"
  if [ "${IS_DATABASE_RESTORE}" == "true" ] && [ "${IS_DB_TYPE}" == "postgres" ]; then
    if [ -z "${IS_DATABASE_ADMIN_USER}" ] || [ -z "${IS_DATABASE_ADMIN_PASSWORD}" ]; then
      logError "246" "DATABASE_ADMIN_USER and/or DATABASE_ADMIN_PASSWORD are blank - skipping checks."
      SKIP_AR_DB_CHECKS=1
    fi
    JISQL_USERNAME="${IS_DATABASE_ADMIN_USER}"
    JISQL_PASSWORD="${IS_DATABASE_ADMIN_PASSWORD}"
    JISQL_DB_NAME="postgres"
  fi
  [[ -n "${SKIP_AR_DB_CHECKS}" ]] && return
  if [ -f dbjars.tgz ]; then
    logMessage "Found dbjars.tgz - running DB checks." 1
    logMessage "Unpacking dbjars.tgz..." 1
    ${TAR_BIN} zxf dbjars.tgz
    buildJISQLcmd
    logMessage "Connecting to '${JISQLURL}' as '${JISQL_USERNAME}'..." 1
    if [ "${IS_DB_TYPE}" == "postgres" ] && [ "${IS_DATABASE_RESTORE}" == "true" ]; then
      SQL_RESULT=$($JISQLCMD "select 1
    go" 2>&1)
    else
      SQL_RESULT=$($JISQLCMD "select currDbVersion from control
    go" 2>&1)
    fi

    if echo "${SQL_RESULT}" | grep -q ErrorCode ; then
     logError "180" "Problem connecting to database - please review the following message."
     echo "${SQL_RESULT}"
     return
    else
      DB_VERSION=$(echo "${SQL_RESULT}" | awk '{print $1}')
      if [ -z "${DB_VERSION}" ] || ! [[ "${DB_VERSION}" =~ ^[0-9]+$ ]]; then
        logError "269" "Blank or unexpected currDbVersion found in control table - check the database is valid."
        return
      fi
      if [ -n "${IS_DB_VERSION}" ]; then
        if [ "${DB_VERSION}" != "${IS_DB_VERSION}" ] && [ "${DB_VERSION}" != "1" ]; then
          logError "181" "Database is not the expected version - found '${DB_VERSION}' but expected '${IS_DB_VERSION}'.  This is expected when running an upgrade."
        else
          if [ "${DB_VERSION}" != "1" ]; then
            logMessage "Database is the expected version - '${DB_VERSION}'." 1
          else
            logMessage "DATABASE_RESTORE selected so skipping currDbVersion check." 1
          fi
        fi
      else
        logMessage "Database currDbVersion is '${DB_VERSION}'." 1
      fi
    fi

    case "${IS_DB_TYPE}" in
      mssql)
        SQL_RESULT=$(${JISQLCMD} "SELECT name FROM sys.synonyms
        go" 2>&1)
        if ! echo "${SQL_RESULT}" | grep -q trace_xe_action_map; then
            logError "182" "Missing 'trace_xe_action_map' synonym in database - please refer to the BMC docs."
        fi
        if ! echo "${SQL_RESULT}" | grep -q trace_xe_event_map; then
            logError "182" "Missing 'trace_xe_event_map' synonym in database - please refer to the BMC docs."
        fi
        ;;
    esac

  else
    logMessage "DB jar files not found - skipping checks.  Download dbjars.tgz to the HITT directory to enable them..."
  fi
}

testdbResolveDbjarsDir() {
  local candidate
  if [[ -n "${DBJARS_TGZ}" && -f "${DBJARS_TGZ}" ]]; then
    cd "$(dirname "${DBJARS_TGZ}")" && pwd
    return 0
  fi
  for candidate in "${PWD}" "${SCRIPT_DIR}"; do
    if [[ -f "${candidate}/dbjars.tgz" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  printf '%s\n' "${PWD}"
}

testdbValidateSettings() {
  local missing=()
  [[ -z "${IS_DATABASE_HOST_NAME:-}" ]] && missing+=("host (--host or IS_DATABASE_HOST_NAME)")
  [[ -z "${IS_DB_PORT:-}" ]] && missing+=("port (--port or IS_DB_PORT)")
  [[ -z "${IS_DB_TYPE:-}" ]] && missing+=("type (--type or IS_DB_TYPE)")
  [[ -z "${IS_AR_DB_USER:-}" ]] && missing+=("user (--user or IS_AR_DB_USER)")
  [[ -z "${IS_AR_DB_PASSWORD:-}" ]] && missing+=("password (--password or IS_AR_DB_PASSWORD)")
  if [[ "${IS_DB_TYPE:-}" == "postgres" && "${IS_DATABASE_RESTORE}" != "true" ]]; then
    [[ -z "${IS_AR_DB_NAME:-}" ]] && missing+=("dbname (--dbname or IS_AR_DB_NAME)")
  fi
  if [[ "${IS_DB_TYPE:-}" == "oracle" ]]; then
    [[ -z "${IS_ORACLE_SERVICE_NAME:-}" ]] && missing+=("oracle service (--oracle-service or IS_ORACLE_SERVICE_NAME)")
  fi
  if ((${#missing[@]} > 0)); then
    logError "999" "Missing required setting(s): ${missing[*]}" 1
  fi
  case "${IS_DB_TYPE}" in
    mssql|oracle|postgres) ;;
    *)
      logError "999" "Invalid IS_DB_TYPE '${IS_DB_TYPE}' — use mssql, oracle, or postgres." 1
      ;;
  esac
  if ! [[ "${IS_DB_PORT}" =~ ^[0-9]+$ ]]; then
    logError "999" "IS_DB_PORT must be a number, not '${IS_DB_PORT}'." 1
  fi
}

testdbUsage() {
  cat <<EOF
Helix IS database test (same checks as HITT checkISDBSettings)

Usage:
  bash testdb.sh [options]

Options:
  --host HOST              Database host (IS_DATABASE_HOST_NAME)
  --port PORT              Database port (IS_DB_PORT)
  --type TYPE              mssql | oracle | postgres (IS_DB_TYPE)
  --user USER              AR database user (IS_AR_DB_USER)
  --password PASS          AR database password (IS_AR_DB_PASSWORD)
  --dbname NAME            AR database name (IS_AR_DB_NAME)
  --oracle-service NAME    Oracle service name (IS_ORACLE_SERVICE_NAME)
  --db-version VER         Expected currDbVersion (IS_DB_VERSION, optional)
  --database-restore       Set IS_DATABASE_RESTORE=true (postgres restore flow)
  --admin-user USER        Postgres admin user when --database-restore
  --admin-password PASS    Postgres admin password when --database-restore
  --config FILE            Source a shell file exporting IS_* variables
  --dbjars PATH            Path to dbjars.tgz (default: ./dbjars.tgz or next to testdb.sh)
  -h, --help               Show this help

Examples:
  bash testdb.sh --host sql.example.com --port 1433 --type mssql \\
    --user Demo --password 'secret' --dbname ARSystem

  bash testdb.sh --config ./pipeline-db.env

Requires dbjars.tgz for JDBC checks:
  curl -skO https://raw.githubusercontent.com/mwaltersbmc/helix-tools/main/hitt/dbjars.tgz
EOF
}

testdbLoadConfig() {
  local config_file=$1
  [[ -f "${config_file}" ]] || logError "999" "Config file '${config_file}' not found." 1
  # shellcheck disable=SC1090
  source "${config_file}"
}

main() {
  local config_file="" dbjars_dir

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --host) IS_DATABASE_HOST_NAME=$2; shift 2 ;;
      --port) IS_DB_PORT=$2; shift 2 ;;
      --type) IS_DB_TYPE=$2; shift 2 ;;
      --user) IS_AR_DB_USER=$2; shift 2 ;;
      --password) IS_AR_DB_PASSWORD=$2; shift 2 ;;
      --dbname) IS_AR_DB_NAME=$2; shift 2 ;;
      --oracle-service) IS_ORACLE_SERVICE_NAME=$2; shift 2 ;;
      --db-version) IS_DB_VERSION=$2; shift 2 ;;
      --database-restore) IS_DATABASE_RESTORE=true; shift ;;
      --admin-user) IS_DATABASE_ADMIN_USER=$2; shift 2 ;;
      --admin-password) IS_DATABASE_ADMIN_PASSWORD=$2; shift 2 ;;
      --config) config_file=$2; shift 2 ;;
      --dbjars) DBJARS_TGZ=$2; shift 2 ;;
      -h|--help) testdbUsage; exit 0 ;;
      *) logError "999" "Unknown option '${1}'." 1 ;;
    esac
  done

  [[ -n "${config_file}" ]] && testdbLoadConfig "${config_file}"

  testdbValidateSettings

  dbjars_dir=$(testdbResolveDbjarsDir)

  logStatus "Helix IS database check"
  logMessage "Host: ${IS_DATABASE_HOST_NAME}:${IS_DB_PORT} (${IS_DB_TYPE})" 0
  logMessage "Working directory for dbjars: ${dbjars_dir}" 1

  (
    cd "${dbjars_dir}" || exit 1
    checkISDBSettings
  )

  if (( FAIL > 0 )); then
    logStatus "Finished with ${FAIL} error(s) and ${WARN} warning(s)."
    exit 1
  fi
  if [[ -n "${SKIP_DB_CHECKS:-}" ]]; then
    logStatus "Finished — DB server not reachable from this host (${WARN} warning(s))."
    exit 2
  fi
  logStatus "Finished — database checks passed (${WARN} warning(s))."
}

main "$@"
