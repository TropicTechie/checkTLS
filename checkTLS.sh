#!/bin/bash

set -o pipefail

print_usage() {
  cat <<EOF
Usage: $0 [options] <endpoints_file | endpoint:port [endpoint:port ...]>

Options:
  -t, --timeout SECONDS   Per-connection timeout (default: 5)
  -f, --format FORMAT     Output format: text|json|csv (default: text)
      --no-sni            Disable SNI (Server Name Indication)
      --cert-info         Include certificate subject/issuer/validity for supported connections
  -j, --jobs N            Number of concurrent endpoints to check (default: 1)
  -h, --help              Show this help

Inputs:
  - File mode: provide a path to an endpoints file with one endpoint:port per line
  - Arg  mode: provide one or more endpoint:port arguments directly
EOF
}

TIMEOUT_SECS=5
FORMAT="text"
USE_SNI=1
INCLUDE_CERT_INFO=0
JOBS=1

ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--timeout)
      TIMEOUT_SECS="$2"; shift 2 ;;
    -f|--format)
      FORMAT="$2"; shift 2 ;;
    --no-sni)
      USE_SNI=0; shift ;;
    --cert-info)
      INCLUDE_CERT_INFO=1; shift ;;
    -j|--jobs)
      JOBS="$2"; shift 2 ;;
    -h|--help)
      print_usage; exit 0 ;;
    --)
      shift; break ;;
    -* )
      echo "Unknown option: $1" >&2; print_usage; exit 2 ;;
    * )
      ARGS+=("$1"); shift ;;
  esac
done

set -- "${ARGS[@]}" "$@"

if [ "$#" -lt 1 ]; then
  echo "Error: provide a endpoints file or one or more endpoint:port entries" 1>&2
  print_usage
  exit 1
fi

TARGETS_FILE=$(mktemp)
trap 'rm -f "$TARGETS_FILE"' EXIT

if [ "$#" -eq 1 ] && [ -f "$1" ]; then
  HOSTS_FILE=$1
  if [ ! -r "$HOSTS_FILE" ]; then
    echo "Error: File $HOSTS_FILE is not readable." 1>&2
    exit 1
  fi
  grep -v '^[[:space:]]*$' "$HOSTS_FILE" | sed 's/#.*$//' | \
    awk -F: 'NF==2{gsub(/[[:space:]]+/, "", $1); gsub(/[[:space:]]+/, "", $2); if($1 != "" && $2 ~ /^[0-9]+$/){ port=$2+0; if(port>=1 && port<=65535) print tolower($1) ":" port }}' | \
    sort -u > "$TARGETS_FILE"
else
  for token in "$@"; do
    if printf '%s' "$token" | grep -q '^[^:][^:]*:[0-9][0-9]*$'; then
      endpoint_part=${token%%:*}
      port_part=${token##*:}
      endpoint_part=$(printf '%s' "$endpoint_part" | tr 'A-Z' 'a-z' | sed 's/[[:space:]]//g')
      port_part=$(printf '%s' "$port_part" | sed 's/[[:space:]]//g')
      if ! printf '%s' "$port_part" | grep -qE '^[0-9]+$' || [ "$port_part" -lt 1 ] || [ "$port_part" -gt 65535 ]; then
        echo "Warning: ignoring invalid port '$port_part' for target '$token' (must be 1-65535)" 1>&2
        continue
      fi
      if [ -n "$endpoint_part" ] && [ -n "$port_part" ]; then
        printf '%s:%s\n' "$endpoint_part" "$port_part" >> "$TARGETS_FILE"
      fi
    else
      echo "Warning: ignoring invalid target '$token' (expected endpoint:port)" 1>&2
    fi
  done
  sort -u "$TARGETS_FILE" -o "$TARGETS_FILE"
fi

TLS_VERSIONS=("tls1" "tls1_1" "tls1_2" "tls1_3")

is_ipv4() {
  printf '%s' "$1" | grep -qE '^[0-9]+(\.[0-9]+){3}$'
}

can_resolve_endpoint() {
  local endpoint="$1"
  if is_ipv4 "$endpoint"; then
    return 0
  fi
  if command -v host >/dev/null 2>&1; then
    if host "$endpoint" 2>/dev/null | grep -qE 'has address|has IPv6 address'; then
      return 0
    fi
  fi
  if command -v dig >/dev/null 2>&1; then
    local ans
    ans=$(dig +short "$endpoint" A "$endpoint" AAAA 2>/dev/null | sed '/^$/d' | head -n1)
    [ -n "$ans" ] && return 0
  fi
  if command -v nslookup >/dev/null 2>&1; then
    if nslookup "$endpoint" 2>/dev/null | grep -qE '^Address: [0-9A-Fa-f:.]+'; then
      return 0
    fi
  fi
  return 1
}

run_with_timeout() {
  local seconds="$1"; shift
  local cmd=("$@")
  local stdout_file stderr_file
  stdout_file=$(mktemp)
  stderr_file=$(mktemp)

  "${cmd[@]}" >"$stdout_file" 2>"$stderr_file" &
  local pid=$!
  local elapsed=0
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$elapsed" -ge "$seconds" ]; then
      kill -TERM "$pid" 2>/dev/null || true
      sleep 0.5
      kill -KILL "$pid" 2>/dev/null || true
      echo "__TIMEOUT__"; cat "$stdout_file"; cat "$stderr_file" 1>&2
      rm -f "$stdout_file" "$stderr_file"
      return 124
    fi
    sleep 1
    elapsed=$((elapsed+1))
  done
  wait "$pid"
  local rc=$?
  cat "$stdout_file"; cat "$stderr_file" 1>&2
  rm -f "$stdout_file" "$stderr_file"
  return $rc
}

humanize_openssl_error() {
  local endpoint="$1" port="$2" raw="$3"
  local msg=""

  local lower
  lower=$(printf '%s' "$raw" | tr 'A-Z' 'a-z')

  if printf '%s' "$lower" | grep -q "__timeout__"; then
    echo "Connection timed out after ${TIMEOUT_SECS}s (no response from ${endpoint}:${port})."
    return
  fi

  if printf '%s' "$lower" | grep -q "bio_lookup_ex"; then
    if printf '%s' "$lower" | grep -q "nodename nor servname provided"; then
      echo "DNS or service lookup failed: the endpointname or port is not recognized (check ${endpoint} and ${port})."
      return
    fi
    echo "Address lookup failed while resolving ${endpoint}:${port}."
    return
  fi

  if printf '%s' "$lower" | grep -q "connection refused\|connect:errno=61"; then
    echo "Connection refused: the service on ${endpoint}:${port} rejected the TCP connection."
    return
  fi
  if printf '%s' "$lower" | grep -q "no route to endpoint\|endpoint is down\|network is unreachable"; then
    echo "Network unreachable: cannot reach ${endpoint}:${port} from this machine."
    return
  fi
  if printf '%s' "$lower" | grep -q "operation timed out\|timed out"; then
    echo "Connection timed out reaching ${endpoint}:${port}."
    return
  fi
  if printf '%s' "$lower" | grep -q "connection reset by peer\|errno=54\|unexpected eof"; then
    echo "Connection reset: the server closed the connection unexpectedly during handshake."
    return
  fi

  if printf '%s' "$lower" | grep -q "alert handshake failure"; then
    echo "TLS handshake failed: the server rejected the handshake (possible cipher/SNI/mTLS mismatch)."
    return
  fi
  if printf '%s' "$lower" | grep -q "certificate verify failed\|unable to get local issuer certificate\|self signed certificate"; then
    echo "Certificate verification failed: the server certificate could not be validated."
    return
  fi

  if printf '%s' "$lower" | grep -q "wrong version number\|protocol version"; then
    echo "Requested TLS version is not supported by the server."
    return
  fi

  msg=$(printf '%s' "$raw" | awk 'length>0{print; exit}')
  if [ -n "$msg" ]; then
    echo "$msg"
  else
    echo "Unknown error occurred while connecting to ${endpoint}:${port}."
  fi
}

probe_tls_version() {
  local endpoint="$1" port="$2" version="$3"
  local sni_args=()
  if [ "$USE_SNI" -eq 1 ]; then
    sni_args=( -servername "$endpoint" )
  fi

  local output rc
  output=$(run_with_timeout "$TIMEOUT_SECS" openssl s_client -connect "${endpoint}:${port}" -${version} "${sni_args[@]}" < /dev/null 2>&1)
  rc=$?

  if [ "$rc" -eq 124 ]; then
    echo "TIMEOUT"
    return 124
  fi

  if [ "$rc" -eq 0 ]; then
    echo "SUPPORTED"
    return 0
  fi

  if echo "$output" | grep -qiE "no protocols available|wrong version number|handshake failure|alert protocol version|protocol version"; then
    echo "NOT_SUPPORTED"
    return 2
  fi

  local friendly
  friendly=$(humanize_openssl_error "$endpoint" "$port" "$output")
  echo "ERROR: ${friendly}"
  return 1
}

get_negotiated_params() {
  local endpoint="$1" port="$2" version="$3"
  local sni_args=()
  if [ "$USE_SNI" -eq 1 ]; then
    sni_args=( -servername "$endpoint" )
  fi
  local output_brief proto cipher
  output_brief=$(run_with_timeout "$TIMEOUT_SECS" openssl s_client -connect "${endpoint}:${port}" -${version} "${sni_args[@]}" -brief < /dev/null 2>&1) || true
  proto=$(echo "$output_brief" | awk -F': *' 'tolower($1)~/^protocol/ {print $2; exit}')
  cipher=$(echo "$output_brief" | awk -F': *' 'tolower($1)~/^cipher/ {print $2; exit}')
  printf '%s|%s' "$proto" "$cipher"
}

extract_cert_info() {
  local endpoint="$1" port="$2" version="$3"
  local sni_args=()
  if [ "$USE_SNI" -eq 1 ]; then
    sni_args=( -servername "$endpoint" )
  fi
  local output_certs cert
  output_certs=$(run_with_timeout "$TIMEOUT_SECS" openssl s_client -connect "${endpoint}:${port}" -${version} "${sni_args[@]}" -showcerts < /dev/null 2>/dev/null) || true
  cert=$(echo "$output_certs" | awk '/-----BEGIN CERTIFICATE-----/{flag=1} flag{print} /-----END CERTIFICATE-----/{flag=0}' | sed '/^$/d' | sed -n '1,/-----END CERTIFICATE-----/p')
  if [ -n "$cert" ]; then
    local subj_dn subj_cn
    subj_dn=$(echo "$cert" | openssl x509 -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//')
    subj_cn=$(echo "$subj_dn" | awk -F',' '{
      cn="";
      for(i=1;i<=NF;i++){
        if($i ~ /^CN=/){ sub(/^CN=/, "", $i); cn=$i }
      }
      if(cn!=""){ print cn } else { print $0 }
    }')
    subj_cn=$(echo "$subj_cn" | sed 's/^ *//; s/ *$//')
    printf '    subject=%s\n' "$subj_cn"

    local issuer_dn issuer_name
    issuer_dn=$(echo "$cert" | openssl x509 -noout -issuer -nameopt RFC2253 2>/dev/null | sed 's/^issuer=//')
    issuer_name=$(echo "$issuer_dn" | awk -F',' '{
      o=""; cn="";
      for(i=1;i<=NF;i++){
        if($i ~ /^O=/){ sub(/^O=/, "", $i); o=$i }
        if($i ~ /^CN=/){ sub(/^CN=/, "", $i); cn=$i }
      }
      if(o!=""){ print o } else if(cn!=""){ print cn } else { print $0 }
    }' | sed 's/\\$//; s/^ *//; s/ *$//')
    printf '    issuer=%s\n' "$issuer_name"

    local not_after now_epoch exp_epoch days
    not_after=$(echo "$cert" | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')
    now_epoch=$(date -u +%s 2>/dev/null)
    if exp_epoch=$(date -u -j -f "%b %e %H:%M:%S %Y %Z" "$not_after" +%s 2>/dev/null); then
      if [ -n "$now_epoch" ] && [ -n "$exp_epoch" ]; then
        days=$(( (exp_epoch - now_epoch + 86399) / 86400 ))
        printf '    days_to_expire=%s\n' "$days"
      fi
    fi
  fi
}

emit_result() {
  local endpoint="$1" port="$2" version="$3" status="$4" proto="$5" cipher="$6" cert_info="$7"
  case "$FORMAT" in
    text)
      if [ -n "$endpoint" ] && [ -n "$port" ] && [ -n "$version" ]; then
        if [ "$status" = "SUPPORTED" ]; then
          echo "  TLS version ${version} is supported on ${endpoint}:${port}"
          [ -n "$cipher" ] && echo "    cert cypher=$cipher"
        elif [ "$status" = "NOT_SUPPORTED" ]; then
          echo "  TLS version ${version} is NOT supported on ${endpoint}:${port}"
        else
          echo "  TLS version ${version} check on ${endpoint}:${port}: ${status}"
        fi
        if [ "$INCLUDE_CERT_INFO" -eq 1 ] && [ "$status" = "SUPPORTED" ] && [ -n "$cert_info" ]; then
          echo "$cert_info"
        fi
      else
        echo "Checking TLS support for ${endpoint}:${port}..."
      fi
      ;;
    json)
      local cert_json="null"
      if [ "$INCLUDE_CERT_INFO" -eq 1 ] && [ -n "$cert_info" ]; then
        if command -v python3 >/dev/null 2>&1; then
          cert_json=$(printf '%s' "$cert_info" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')
        elif command -v python >/dev/null 2>&1; then
          cert_json=$(printf '%s' "$cert_info" | python -c 'import json,sys; print(json.dumps(sys.stdin.read()))')
        elif command -v jq >/dev/null 2>&1; then
          cert_json=$(printf '%s' "$cert_info" | jq -Rs .)
        else
          local esc
          esc=$(printf '%s' "$cert_info" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a;N;$!ba;s/\n/\\n/g' -e 's/\r/\\r/g')
          cert_json="\"$esc\""
        fi
      fi
      printf '{"endpoint":"%s","port":%s,"version":"%s","status":"%s","protocol":%s,"cipher":%s,"cert_info":%s}\n' \
        "$endpoint" "$port" "$version" "$status" \
        "$( [ -n "$proto" ] && printf '"%s"' "$proto" || printf 'null')" \
        "$( [ -n "$cipher" ] && printf '"%s"' "$cipher" || printf 'null')" \
        "$cert_json"
      ;;
    csv)
      printf '%s,%s,%s,%s,%s,%s\n' "$endpoint" "$port" "$version" "$status" "$proto" "$cipher"
      ;;
    *)
      echo "Error: unknown format $FORMAT" 1>&2
      exit 2
      ;;
  esac
}

check_endpoint() {
  local endpoint="$1" port="$2"
  if ! can_resolve_endpoint "$endpoint"; then
    if [ "$FORMAT" = "text" ]; then
      echo "Error: Cannot resolve endpoint: ${endpoint}"
      echo "Skipping checks for invalid endpoint: ${endpoint}:${port}"
      echo "-------------------------------------"
      echo ""
    fi
    return
  fi
  if [ "$FORMAT" = "text" ]; then
    echo "Checking TLS support for ${endpoint}:${port}..."
  fi
  local version
  for version in "${TLS_VERSIONS[@]}"; do
    local status
    status=$(probe_tls_version "$endpoint" "$port" "$version")
    local rc=$?
    local proto="" cipher="" cert_info=""
    if [ "$status" = "SUPPORTED" ]; then
      IFS='|' read -r proto cipher <<< "$(get_negotiated_params "$endpoint" "$port" "$version")"
      if [ "$INCLUDE_CERT_INFO" -eq 1 ]; then
        cert_info=$(extract_cert_info "$endpoint" "$port" "$version")
      fi
    fi
    emit_result "$endpoint" "$port" "$version" "$status" "$proto" "$cipher" "$cert_info"
  done
  if [ "$FORMAT" = "text" ]; then
    echo "-------------------------------------"
    echo ""
  fi
}

if [ "$FORMAT" = "csv" ]; then
  echo "endpoint,port,version,status,protocol,cipher"
fi

if [ "$JOBS" -le 1 ]; then
  while IFS=":" read -r HOST PORT; do
    [ -z "$HOST" ] && continue
    check_endpoint "$HOST" "$PORT"
  done < "$TARGETS_FILE"
else
  batch_count=0
  pids=()
  while IFS=":" read -r HOST PORT; do
    [ -z "$HOST" ] && continue
    check_endpoint "$HOST" "$PORT" &
    pids+=("$!")
    batch_count=$((batch_count+1))
    if [ "$batch_count" -ge "$JOBS" ]; then
      for pid in "${pids[@]}"; do
        wait "$pid" || true
      done
      pids=()
      batch_count=0
    fi
  done < "$TARGETS_FILE"
  for pid in "${pids[@]}"; do
    wait "$pid" || true
  done
fi
