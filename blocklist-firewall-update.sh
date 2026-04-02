#!/bin/sh
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
set -eu

DRY_RUN=0


# ── Load config file ───────────────────────────────────────────────────────────
if [ -z "${CONFIG_FILE:-}" ]; then
  if [ -f "$(dirname "$0")/blocklist-firewall-update.conf" ]; then
    CONFIG_FILE="$(dirname "$0")/blocklist-firewall-update.conf"
  elif [ -f "/etc/blocklist-firewall-update.conf" ]; then
    CONFIG_FILE="/etc/blocklist-firewall-update.conf"
  fi
fi
if [ -n "${CONFIG_FILE:-}" ] && [ -f "$CONFIG_FILE" ]; then
  # shellcheck source=/dev/null
  . "$CONFIG_FILE"
fi


# ── Parse command-line options (override config file settings) ─────────────────
while [ $# -gt 0 ]; do
  case "$1" in
    -n|--dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      echo "Usage: $(basename "$0") [OPTIONS]"
      echo "Options:"
      echo "  -n, --dry-run    Print commands without applying them"
      echo "  -h, --help       Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

# Wrapper for running or echoing commands depending on dry-run mode
run_cmd() {
  if [ "$DRY_RUN" = "1" ]; then
    echo "+ $*"
  else
    eval "$*"
  fi
}


# ── Defaults (applied when not set by config file or environment) ──────────────
BLOCKLIST_CHAIN_NAME="${BLOCKLIST_CHAIN_NAME:-BLOCKLIST_INPUT}"

ENABLE_BLOCKLIST_DE="${ENABLE_BLOCKLIST_DE:-yes}"
BLOCKLIST_DE_TYPES="${BLOCKLIST_DE_TYPES:-ssh,bruteforcelogin}"

ENABLE_ABUSEIPDB="${ENABLE_ABUSEIPDB:-no}"
ABUSEIPDB_API_KEY="${ABUSEIPDB_API_KEY:-}"
ABUSEIPDB_CONFIDENCE_MINIMUM="${ABUSEIPDB_CONFIDENCE_MINIMUM:-90}"

ENABLE_DSHIELD="${ENABLE_DSHIELD:-no}"
DSHIELD_URL="${DSHIELD_URL:-https://feeds.dshield.org/block.txt}"

ENABLE_FIREHOL="${ENABLE_FIREHOL:-no}"
FIREHOL_SETS="${FIREHOL_SETS:-firehol_level1 firehol_level2}"
FIREHOL_BASE_URL="${FIREHOL_BASE_URL:-https://raw.githubusercontent.com/firehol/blocklist-ipsets/master}"

ENABLE_THREATFOX="${ENABLE_THREATFOX:-no}"
THREATFOX_DAYS="${THREATFOX_DAYS:-7}"


CHAIN_NAME="$BLOCKLIST_CHAIN_NAME"
TMP_DIR="$(mktemp -d /tmp/blocklist.XXXXXX)"

log() {
  printf '%s %s\n' "$(date +%Y%m%d-%H%M) [blocklist]" "$*"
}

for tool in curl ipset iptables; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    log "$tool not found"
    exit 1
  fi
done

trap 'rm -rf "$TMP_DIR"' EXIT

# Space-separated list of ipset names successfully updated this run.
# Each name gets its own match-set rule in the iptables chain.
ACTIVE_SETS=""


# ── Helper: validate, populate and atomically swap one ipset ──────────────────
# update_ipset <set_name> <raw_file>
#   Reads <raw_file>, keeps valid IPv4/CIDR entries, loads into <set_name>
#   via a temporary set and atomic swap. Logs per-set stats.
update_ipset() {
  local set_name="$1"
  local raw_file="$2"
  local clean_file="${TMP_DIR}/clean_${set_name}.txt"
  local prev_file="${TMP_DIR}/prev_${set_name}.txt"
  local tmp_set="${set_name}_tmp"

  # Keep only valid IPv4 addresses and CIDR blocks.
  grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$' "$raw_file" \
    | awk -F'[./]' '
        $1<=255 && $2<=255 && $3<=255 && $4<=255 &&
        (NF==4 || (NF==5 && $5+0>=1 && $5+0<=32))
      ' \
    | sort -u > "$clean_file"

  # Snapshot current members for diff.
  if ipset list "$set_name" 2>/dev/null | grep -q 'Members:'; then
    ipset list "$set_name" \
      | awk '/Members:/ {found=1; next} found && NF {print $1}' \
      | sort -u > "$prev_file"
  else
    : > "$prev_file"
  fi

  # Migrate hash:ip → hash:net if needed (hash:net supports CIDR; one-time).
  for _s in "$set_name" "$tmp_set"; do
    if ipset list "$_s" 2>/dev/null | grep -q 'Type: hash:ip'; then
      log "Migrating '${_s}' from hash:ip to hash:net"
      iptables -D "$CHAIN_NAME" -m set --match-set "$_s" src -j DROP 2>/dev/null || true
      ipset destroy "$_s" 2>/dev/null || true
    fi
  done

  # Populate via temporary set and perform atomic swap.
  run_cmd "ipset create '${set_name}' hash:net family inet -exist"
  run_cmd "ipset create '${tmp_set}' hash:net family inet -exist"
  run_cmd "ipset flush '${tmp_set}'"

  while IFS= read -r entry; do
    [ -n "$entry" ] || continue
    run_cmd "ipset add '${tmp_set}' '${entry}' -exist"
  done < "$clean_file"

  run_cmd "ipset swap '${set_name}' '${tmp_set}'"
  run_cmd "ipset flush '${tmp_set}'"

  # Per-set stats.
  local curr added removed delta
  curr=$(wc -l < "$clean_file")
  added=$(comm -13 "$prev_file" "$clean_file" | wc -l)
  removed=$(comm -23 "$prev_file" "$clean_file" | wc -l)
  delta=$((added - removed))
  log "${set_name}: $((curr+0)) entries (+$((added+0))/-$((removed+0)), net $((delta+0)))"
}


# ── blocklist.de  →  ipset: blocklist_de ──────────────────────────────────────
if [ "$ENABLE_BLOCKLIST_DE" = "yes" ]; then
  raw="${TMP_DIR}/raw_de.txt"
  : > "$raw"
  ok=0
  TYPES_LIST="$(printf '%s' "$BLOCKLIST_DE_TYPES" | tr ',;' '  ')"
  for type in $TYPES_LIST; do
    case "$type" in
      all|ssh|mail|apache|imap|ftp|sip|bots|strongips|ircbot|bruteforcelogin) ;;
      *)
        log "blocklist.de: invalid type '${type}', skipping"
        continue
        ;;
    esac
    type_file="${TMP_DIR}/de_${type}.txt"
    if curl -fsSL --connect-timeout 15 --max-time 120 \
        "https://lists.blocklist.de/lists/${type}.txt" -o "$type_file"; then
      cat "$type_file" >> "$raw"
      ok=$((ok + 1))
    else
      log "blocklist.de/${type}: download failed, skipping"
    fi
  done
  if [ "$ok" -gt 0 ]; then
    update_ipset "blocklist_de" "$raw"
    ACTIVE_SETS="${ACTIVE_SETS} blocklist_de"
  fi
fi


# ── AbuseIPDB  →  ipset: abuseipdb_com ────────────────────────────────────────
if [ "$ENABLE_ABUSEIPDB" = "yes" ]; then
  if [ -z "$ABUSEIPDB_API_KEY" ]; then
    log "AbuseIPDB: ABUSEIPDB_API_KEY is not set, skipping"
  else
    raw="${TMP_DIR}/raw_abuseipdb.txt"
    if curl -fsSL --connect-timeout 15 --max-time 120 \
        -G "https://api.abuseipdb.com/api/v2/blacklist" \
        -d "confidenceMinimum=${ABUSEIPDB_CONFIDENCE_MINIMUM}" \
        -H "Key: ${ABUSEIPDB_API_KEY}" \
        -H "Accept: text/plain" \
        -o "$raw"; then
      update_ipset "abuseipdb_com" "$raw"
      ACTIVE_SETS="${ACTIVE_SETS} abuseipdb_com"
    else
      log "AbuseIPDB: download failed, skipping"
    fi
  fi
fi


# ── DShield  →  ipset: dshield_org ────────────────────────────────────────────
# block.txt: tab-separated StartIP / EndIP / PrefixLen; also handles CIDR lines.
if [ "$ENABLE_DSHIELD" = "yes" ]; then
  raw="${TMP_DIR}/raw_dshield.txt"
  raw_parsed="${TMP_DIR}/raw_dshield_parsed.txt"
  if curl -fsSL --connect-timeout 15 --max-time 120 "$DSHIELD_URL" -o "$raw"; then
    awk '
      /^[[:space:]]*#/ { next }
      /^[0-9][0-9.]*\/[0-9]/ { print $1; next }
      NF >= 3 && $1 ~ /^[0-9]/ && $3 ~ /^[0-9]+$/ { print $1 "/" $3 }
    ' "$raw" > "$raw_parsed"
    update_ipset "dshield_org" "$raw_parsed"
    ACTIVE_SETS="${ACTIVE_SETS} dshield_org"
  else
    log "DShield: download failed, skipping"
  fi
fi


# ── FireHOL  →  ipset per set (e.g. firehol_level1, firehol_level2) ───────────
# Each name in FIREHOL_SETS becomes its own ipset with the same name.
# .netset is tried first, then .ipset.
if [ "$ENABLE_FIREHOL" = "yes" ]; then
  for fset in $FIREHOL_SETS; do
    raw="${TMP_DIR}/raw_firehol_${fset}.txt"
    raw_clean="${TMP_DIR}/raw_firehol_${fset}_clean.txt"
    downloaded=0
    for ext in netset ipset; do
      url="${FIREHOL_BASE_URL}/${fset}.${ext}"
      if curl -fsSL --connect-timeout 15 --max-time 120 "$url" -o "$raw" 2>/dev/null; then
        downloaded=1
        break
      fi
    done
    if [ "$downloaded" = "1" ]; then
      grep -v '^[[:space:]]*#' "$raw" | grep -v '^[[:space:]]*$' > "$raw_clean" || true
      update_ipset "$fset" "$raw_clean"
      ACTIVE_SETS="${ACTIVE_SETS} ${fset}"
    else
      log "FireHOL '${fset}': download failed, skipping"
    fi
  done
fi


# ── ThreatFox  →  ipset: threatfox_abuse_ch ───────────────────────────────────
# JSON API, no key required. Extracts IPs from ip:port IOC fields.
if [ "$ENABLE_THREATFOX" = "yes" ]; then
  raw="${TMP_DIR}/raw_threatfox.json"
  raw_parsed="${TMP_DIR}/raw_threatfox.txt"
  if curl -fsSL --connect-timeout 15 --max-time 120 \
      -X POST -H "Content-Type: application/json" \
      -d "{\"query\":\"get_iocs\",\"days\":${THREATFOX_DAYS}}" \
      "https://threatfox-api.abuse.ch/api/v1/" \
      -o "$raw"; then
    grep -oE '"ioc":"[0-9]{1,3}(\.[0-9]{1,3}){3}(:[0-9]+)?"' "$raw" \
      | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' > "$raw_parsed" || true
    update_ipset "threatfox_abuse_ch" "$raw_parsed"
    ACTIVE_SETS="${ACTIVE_SETS} threatfox_abuse_ch"
  else
    log "ThreatFox: download failed, skipping"
  fi
fi


# ── iptables chain ─────────────────────────────────────────────────────────────
# The chain is flushed and rebuilt with one match-set DROP rule per active set.
if [ -z "${ACTIVE_SETS# }" ]; then
  log "Warning: no sources produced results; chain will have no drop rules"
fi

if [ "$DRY_RUN" = "1" ]; then
  echo "+ iptables -N '${CHAIN_NAME}' 2>/dev/null || true"
  echo "+ iptables -F '${CHAIN_NAME}'"
else
  iptables -N "$CHAIN_NAME" 2>/dev/null || true
  iptables -F "$CHAIN_NAME"
fi

for set_name in $ACTIVE_SETS; do
  run_cmd "iptables -A '${CHAIN_NAME}' -m set --match-set '${set_name}' src -j DROP"
done

if [ "$DRY_RUN" = "1" ]; then
  echo "+ iptables -C INPUT -j '${CHAIN_NAME}' >/dev/null 2>&1 || iptables -I INPUT 1 -j '${CHAIN_NAME}'"
else
  if ! iptables -C INPUT -j "$CHAIN_NAME" >/dev/null 2>&1; then
    iptables -I INPUT 1 -j "$CHAIN_NAME"
  fi
fi


# ── Summary ────────────────────────────────────────────────────────────────────
set -- $ACTIVE_SETS
if [ "$#" -gt 0 ]; then
  ACTIVE_SETS_FMT="$*"
else
  ACTIVE_SETS_FMT="none"
fi

log "chain: ${CHAIN_NAME}"
log "active_sets: ${ACTIVE_SETS_FMT}"
echo ""
