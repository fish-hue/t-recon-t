#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# recon_plus_v2.5.sh  —  Termux Recon Tool (Bonus Edition)
# Version: v2.5 - Termux Recon Tool
# Updated: 2025-11-12 By fish-hue
# Note: Use only on targets you own or have explicit permission to test.
# ---------------------------------------------------------------------------

set -euo pipefail
IFS=$'\n\t'

VERSION="v2.5 - Recon Plus (Final Termux Edition)"

# -------------------- Defaults / Config --------------------
TMPDIR="$(mktemp -d -t recon.XXXXXXXX 2>/dev/null || mktemp -d)"
trap 'rc=$?; [[ "${KEEP_TEMP:-no}" != "yes" && -d "$TMPDIR" ]] && rm -rf "$TMPDIR"; exit $rc' EXIT

COLOR="yes"
TIMEOUT_CMD="$(command -v timeout || true)"
DEFAULT_CONCURRENCY=10
CURL_FALLBACK_CONCURRENCY=5
NMAP_PORTS="1-1024"
MASSCAN_RATE=1000

# Flags (defaults)
KEEP_TEMP="no"
OUTDIR=""
ACTIVE="no"
DO_SUBDOMAINS="yes"
DO_HARVEST="no"
DO_NUCLEI="no"
DO_MASSCAN="no"
JSON_OUT="no"
VERBOSE="no"
CONCURRENCY="$DEFAULT_CONCURRENCY"

# -------------------- Helpers --------------------
echoinfo(){ if [[ "$COLOR" == "yes" ]]; then printf "\e[34m[INFO]\e[0m %s\n" "$*"; else printf "[INFO] %s\n" "$*"; fi; }
echowarn(){ if [[ "$COLOR" == "yes" ]]; then printf "\e[33m[WARN]\e[0m %s\n" "$*"; else printf "[WARN] %s\n" "$*"; fi; }
echoerr(){ if [[ "$COLOR" == "yes" ]]; then printf "\e[31m[ERROR]\e[0m %s\n" "$*" >&2; else printf "[ERROR] %s\n" "$*" >&2; fi; }

# require_cmd: returns 0 if available, otherwise prints helpful install hints
require_cmd(){
  local cmd="$1"
  if command -v "$cmd" >/dev/null 2>&1; then
    return 0
  fi
  # If go exists, ensure $HOME/go/bin is in PATH (Termux common)
  if command -v go >/dev/null 2>&1; then
    if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
      export PATH="$PATH:$HOME/go/bin"
      echoinfo "Temporarily adding \$HOME/go/bin to PATH for Go-installed tools."
    fi
    if command -v "$cmd" >/dev/null 2>&1; then
      return 0
    fi
  fi

  # Helpful install suggestions
  echoerr "Command not found: $cmd"
  case "$cmd" in
    subfinder) echoinfo "Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" ;;
    amass) echoinfo "Install: pkg install amass (or go install github.com/owasp-amass/amass/v3/...)" ;;
    gau) echoinfo "Install: go install github.com/lc/gau@latest" ;;
    waybackurls) echoinfo "Install: go install github.com/tomnomnom/waybackurls@latest" ;;
    httprobe) echoinfo "Install: go install github.com/tomnomnom/httprobe@latest" ;;
    nuclei) echoinfo "Install: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest" ;;
    masscan) echoinfo "Install: pkg install masscan (may require privileges)" ;;
    nmap) echoinfo "Install: pkg install nmap" ;;
    whois) echoinfo "Install: pkg install whois" ;;
    dig|nslookup) echoinfo "Install: pkg install dnsutils" ;;
    curl) echoinfo "Install: pkg install curl" ;;
    *) echoinfo "Please install $cmd (Termux: pkg or go install)." ;;
  esac
  return 1
}

# run_with_timeout: uses timeout if available, otherwise runs command
run_with_timeout(){
  local t="$1"; shift
  if [[ -n "$TIMEOUT_CMD" ]]; then
    "$TIMEOUT_CMD" "$t" "$@" || true
  else
    "$@" || true
  fi
}

is_ip_v4(){
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

is_ipv6(){
  [[ "$1" == *:* ]]
}

is_valid_target(){
  local d="$1"
  if is_ip_v4 "$d" || is_ipv6 "$d"; then return 0; fi
  if [[ "$d" =~ ^([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$ ]]; then return 0; fi
  return 1
}

usage(){
  cat <<EOF
recon_plus_v2.5.sh - $VERSION
Usage: $0 -t <target> [--active] [--out DIR] [--keep-temp] [--subdomains (y/n)] [--concurrency N]
Options:
  -t|--target       Target domain or IP (required)
  --active          Enable active scans (nmap/masscan/nuclei) - requires confirmation
  --out DIR         Save outputs to DIR
  --keep-temp       Keep temp files (do not auto-delete)
  --subdomains y|n  Enable (y) or disable (n) passive subdomain discovery (default: y)
  --concurrency N   Concurrency for probes (default: $DEFAULT_CONCURRENCY)
  --help            Show this help
EOF
  exit 1
}

# -------------------- Arg parse --------------------
TARGET=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target) TARGET="${2:-}"; shift 2 ;;
    --active) ACTIVE="yes"; shift ;;
    --out) OUTDIR="${2:-}"; shift 2 ;;
    --keep-temp) KEEP_TEMP="yes"; shift ;;
    --subdomains) shift; DO_SUBDOMAINS="${1:-yes}"; shift ;;
    --concurrency) CONCURRENCY="${2:-$DEFAULT_CONCURRENCY}"; shift 2 ;;
    --help|-h) usage ;;
    *) echoerr "Unknown option: $1"; usage ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echoerr "Target required."
  usage
fi

if ! is_valid_target "$TARGET"; then
  echoerr "Invalid target format: $TARGET"
  exit 2
fi

if [[ -n "$OUTDIR" ]]; then
  mkdir -p "$OUTDIR"
fi

# -------------------- Termux Go PATH fix (if go installed) --------------------
if command -v go >/dev/null 2>&1; then
  if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
    export PATH="$PATH:$HOME/go/bin"
    echoinfo "Temporarily adding \$HOME/go/bin to PATH for Go tools."
  fi
fi

# -------------------- Active confirmation --------------------
if [[ "$ACTIVE" == "yes" ]]; then
  echowarn "Active scans requested — ensure you have permission."
  read -rp "Type YES to confirm authorization for $TARGET: " CONFIRM_ACTIVE
  if [[ "$CONFIRM_ACTIVE" != "YES" ]]; then
    echoerr "Authorization not confirmed. Disabling active components."
    ACTIVE="no"
  fi
fi

echoinfo "Starting recon: $TARGET"
echoinfo "Mode: $( [[ "$ACTIVE" == "yes" ]] && echo "ACTIVE" || echo "PASSIVE only" )"
echoinfo "Tempdir: $TMPDIR"
[[ -n "$OUTDIR" ]] && echoinfo "Outdir: $OUTDIR"

# -------------------- Files & placeholders --------------------
WHOIS_OUT="$TMPDIR/whois.txt"
DIG_A="$TMPDIR/dig_a.txt"
DIG_MX="$TMPDIR/dig_mx.txt"
DIG_NS="$TMPDIR/dig_ns.txt"
DIG_CNAME="$TMPDIR/dig_cname.txt"
DIG_TXT="$TMPDIR/dig_txt.txt"
NSLOOKUP_OUT="$TMPDIR/nslookup.txt"
SUBS_OUT="$TMPDIR/subdomains.txt"
URLS_OUT="$TMPDIR/harvest_urls.txt"
CANDIDATES="$TMPDIR/candidates.txt"
RESPONDERS_OUT="$TMPDIR/responders.txt"
NMAP_OUT="$TMPDIR/nmap.txt"
MASSCAN_OUT="$TMPDIR/masscan.json"
NUCLEI_OUT="$TMPDIR/nuclei.txt"
REPORT_JSON="$TMPDIR/report.json"

# -------------------- WHOIS --------------------
if require_cmd whois; then
  echoinfo "Running whois..."
  run_with_timeout 15 whois "$TARGET" >"$WHOIS_OUT" 2>/dev/null || true
else
  echowarn "whois not available; skipping WHOIS."
fi

# -------------------- DNS queries (parallel, with file checks) --------------------
echoinfo "Querying DNS (dig with timeouts)..."
dig_query_short() {
  # uses dig +short but with conservative timeouts
  if require_cmd dig; then
    # dig output to file
    dig +short +time=3 +tries=1 "$TARGET" "$1" > "$2" 2>/dev/null || true
  fi
}
dig_query_short A "$DIG_A" & dig_query_short MX "$DIG_MX" & dig_query_short NS "$DIG_NS" &
dig_query_short CNAME "$DIG_CNAME" & dig_query_short TXT "$DIG_TXT" & wait

# Parse A
if [[ -s "$DIG_A" ]]; then
  DIG_A_RECORDS="$(awk '{print $1}' "$DIG_A" | sort -u | tr '\n' ' ' | sed 's/ $//')"
else
  DIG_A_RECORDS=""
fi

# Parse MX: dig +short MX typically: "<priority> <exchange>"
if [[ -s "$DIG_MX" ]]; then
  # grab second field (exchange), ignore priority number
  DIG_MX_RECORDS="$(awk '{print $2}' "$DIG_MX" | sed 's/\.$//' | tr '\n' ' ' | sed 's/ $//')"
else
  DIG_MX_RECORDS=""
fi

# Parse NS (first field is fine)
if [[ -s "$DIG_NS" ]]; then
  DIG_NS_RECORDS="$(awk '{print $1}' "$DIG_NS" | sed 's/\.$//' | tr '\n' ' ' | sed 's/ $//')"
else
  DIG_NS_RECORDS=""
fi

# Parse CNAME
if [[ -s "$DIG_CNAME" ]]; then
  DIG_CNAME_RECORDS="$(awk '{print $1}' "$DIG_CNAME" | sed 's/\.$//' | tr '\n' ' ' | sed 's/ $//')"
else
  DIG_CNAME_RECORDS=""
fi

# Parse TXT: remove surrounding quotes cleanly and squash newlines
if [[ -s "$DIG_TXT" ]]; then
  # dig +short TXT often prints each TXT record as one quoted string per line
  DIG_TXT_RECORDS="$(sed -E 's/^"//; s/"$//' "$DIG_TXT" | tr '\n' ' ' | sed 's/  */ /g' | sed 's/ $//')"
else
  DIG_TXT_RECORDS=""
fi

# Optional nslookup
if require_cmd nslookup; then
  echoinfo "Running nslookup..."
  run_with_timeout 6 nslookup "$TARGET" >"$NSLOOKUP_OUT" 2>/dev/null || true
else
  NSLOOKUP_OUT=""
fi

# -------------------- SCAN_TARGET resolution (domain -> IP) --------------------
SCAN_TARGET="$TARGET"
if ! is_ip_v4 "$TARGET" && ! is_ipv6 "$TARGET" && [[ -n "$DIG_A_RECORDS" ]]; then
  FIRST_IP="$(echo "$DIG_A_RECORDS" | awk '{print $1}')"
  if [[ -n "$FIRST_IP" ]]; then
    SCAN_TARGET="$FIRST_IP"
    echoinfo "Active scans will target resolved IP: $SCAN_TARGET"
  fi
fi

# -------------------- Passive Subdomain Discovery (combined) --------------------
if [[ "${DO_SUBDOMAINS,,}" != "n" ]]; then
  echoinfo "Passive subdomain discovery (subfinder + amass if available)..."
  : > "$SUBS_OUT"
  if require_cmd subfinder; then
    echoinfo "Running subfinder..."
    run_with_timeout 120 subfinder -d "$TARGET" -silent -o "$TMPDIR/sub_subfinder.txt"
    [[ -s "$TMPDIR/sub_subfinder.txt" ]] && cat "$TMPDIR/sub_subfinder.txt" >> "$SUBS_OUT"
  fi
  if require_cmd amass; then
    echoinfo "Running amass (passive)..."
    run_with_timeout 180 amass enum -passive -d "$TARGET" -silent -o "$TMPDIR/sub_amass.txt"
    [[ -s "$TMPDIR/sub_amass.txt" ]] && cat "$TMPDIR/sub_amass.txt" >> "$SUBS_OUT"
  fi
  if [[ -s "$SUBS_OUT" ]]; then
    sort -u "$SUBS_OUT" -o "$SUBS_OUT"
    echoinfo "Subdomains found: $(wc -l < "$SUBS_OUT" 2>/dev/null || echo 0)"
  else
    echowarn "No passive subdomain results collected."
  fi
fi

# -------------------- URL Harvest (optional) --------------------
if [[ "$DO_HARVEST" == "yes" ]]; then
  echoinfo "Harvesting URLs (gau / waybackurls) ..."
  if require_cmd gau; then
    run_with_timeout 60 gau "$TARGET" > "$URLS_OUT" || true
  elif require_cmd waybackurls; then
    run_with_timeout 60 waybackurls "$TARGET" > "$URLS_OUT" || true
  else
    echowarn "No URL harvesting tool (gau/waybackurls) found; skipping."
  fi
  [[ -f "$URLS_OUT" ]] && sort -u "$URLS_OUT" -o "$URLS_OUT"
fi

# -------------------- HTTP Probing (httprobe or curl fallback) --------------------
echoinfo "Preparing host candidates for HTTP probing..."
: > "$CANDIDATES"
echo "$TARGET" >> "$CANDIDATES"
if [[ -s "$SUBS_OUT" ]]; then
  cat "$SUBS_OUT" >> "$CANDIDATES"
fi
sort -u "$CANDIDATES" -o "$CANDIDATES" || true

echoinfo "Probing HTTP(S) responders..."
if require_cmd httprobe; then
  cat "$CANDIDATES" | httprobe -c "$CONCURRENCY" > "$RESPONDERS_OUT" || true
else
  echowarn "httprobe not found; using curl fallback with concurrency ${CURL_FALLBACK_CONCURRENCY}."
  # conservative concurrency for mobile devices
  cat "$CANDIDATES" | xargs -P "$CURL_FALLBACK_CONCURRENCY" -n1 -I{} sh -c '
    S="{}"
    curl -I -m 6 -sS "http://$S" >/dev/null 2>&1 && echo "http://$S"
    curl -I -m 6 -sS "https://$S" >/dev/null 2>&1 && echo "https://$S"
  ' > "$RESPONDERS_OUT" || true
fi
[[ -f "$RESPONDERS_OUT" ]] && sort -u "$RESPONDERS_OUT" -o "$RESPONDERS_OUT"

# -------------------- Active Scans: nmap & masscan --------------------
if [[ "$ACTIVE" == "yes" ]]; then
  # Nmap
  if require_cmd nmap; then
    echoinfo "Running nmap (service detection) on $SCAN_TARGET ..."
    run_with_timeout 600 nmap -p "$NMAP_PORTS" -sV --reason -oN "$NMAP_OUT" "$SCAN_TARGET" || true
  else
    echowarn "nmap not installed; skipping nmap scan. (Install: pkg install nmap)"
  fi

  # Masscan (optional)
  if [[ "$DO_MASSCAN" == "yes" ]]; then
    if require_cmd masscan; then
      echoinfo "Running masscan (fast discovery) on $SCAN_TARGET ..."
      # masscan may require additional privileges; run best-effort
      masscan -p1-65535 --rate "$MASSCAN_RATE" "$SCAN_TARGET" -oJ "$MASSCAN_OUT" || true
    else
      echowarn "masscan not installed; skipping masscan. (Install: pkg install masscan)"
    fi
  fi
fi

# -------------------- Optional: nuclei scanning (active) --------------------
if [[ "$DO_NUCLEI" == "yes" && "$ACTIVE" == "yes" ]]; then
  if require_cmd nuclei; then
    echoinfo "Running nuclei (user template control)..."
    if [[ -s "$RESPONDERS_OUT" ]]; then
      run_with_timeout 600 nuclei -l "$RESPONDERS_OUT" -o "$NUCLEI_OUT" || true
    else
      run_with_timeout 600 nuclei -u "$SCAN_TARGET" -o "$NUCLEI_OUT" || true
    fi
  else
    echowarn "nuclei not installed; skipping nuclei. (Install: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest)"
  fi
fi

# -------------------- Build enriched JSON summary --------------------
SUBS_COUNT="$(wc -l < "$SUBS_OUT" 2>/dev/null || echo 0)"
RESP_COUNT="$(wc -l < "$RESPONDERS_OUT" 2>/dev/null || echo 0)"

cat > "$REPORT_JSON" <<JSON
{
  "version": "$VERSION",
  "target": "$TARGET",
  "scan_target": "$SCAN_TARGET",
  "mode": "$( [[ "$ACTIVE" == "yes" ]] && echo "active" || echo "passive" )",
  "dns": {
    "a": "$(printf '%s' "$DIG_A_RECORDS")",
    "mx": "$(printf '%s' "$DIG_MX_RECORDS")",
    "ns": "$(printf '%s' "$DIG_NS_RECORDS")",
    "cname": "$(printf '%s' "$DIG_CNAME_RECORDS")",
    "txt": "$(printf '%s' "$DIG_TXT_RECORDS")"
  },
  "artifact_counts": {
    "subdomains": "$SUBS_COUNT",
    "responders": "$RESP_COUNT"
  },
  "files": {
    "whois": "$( [[ -f "$WHOIS_OUT" ]] && echo "$WHOIS_OUT" || echo "" )",
    "subdomains": "$( [[ -f "$SUBS_OUT" ]] && echo "$SUBS_OUT" || echo "" )",
    "responders": "$( [[ -f "$RESPONDERS_OUT" ]] && echo "$RESPONDERS_OUT" || echo "" )",
    "nmap": "$( [[ -f "$NMAP_OUT" ]] && echo "$NMAP_OUT" || echo "" )",
    "masscan": "$( [[ -f "$MASSCAN_OUT" ]] && echo "$MASSCAN_OUT" || echo "" )",
    "nuclei": "$( [[ -f "$NUCLEI_OUT" ]] && echo "$NUCLEI_OUT" || echo "" )"
  }
}
JSON

echoinfo "JSON summary written to: $REPORT_JSON"

# -------------------- Final cleanup / save prompt --------------------
if [[ -n "$OUTDIR" ]]; then
  echoinfo "Saving all outputs to $OUTDIR"
  mkdir -p "$OUTDIR"
  cp -r "$TMPDIR"/* "$OUTDIR"/ 2>/dev/null || true
  echoinfo "Saved."
elif [[ "$KEEP_TEMP" != "yes" ]]; then
  read -rp "Save temporary outputs to a timestamped folder in current directory? (y/N): " SAVE
  if [[ "${SAVE:-n}" =~ ^[Yy]$ ]]; then
    LOCAL_OUTDIR="./recon_output_$(date +%Y%m%d_%H%M%S)"
    echoinfo "Saving temp files to $LOCAL_OUTDIR"
    mkdir -p "$LOCAL_OUTDIR"
    cp -r "$TMPDIR"/* "$LOCAL_OUTDIR"/ 2>/dev/null || true
    echoinfo "Saved to $LOCAL_OUTDIR"
    # user opted to keep — prevent trap from deleting it
    KEEP_TEMP="yes"
  else
    echoinfo "Temporary outputs will be removed."
  fi
fi

echoinfo "Recon complete. Summary: $SUBS_COUNT subdomains | $RESP_COUNT responders"
# explicit exit to trigger trap cleanup
exit 0
