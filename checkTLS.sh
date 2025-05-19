# Define log file location
LOG_FILE="tls_checks.log"

# Function to log messages with timestamps
log_message() {
    local message="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $message" >> "$LOG_FILE"
}

# Function to validate if a domain is resolvable
validate_domain() {
    local domain=$1
    # Extract hostname part (remove port if present)
    local hostname=${domain%:*}

    # Try to resolve the domain using host command
    if host "$hostname" >/dev/null 2>&1; then
        log_message "Domain validation successful for: $hostname"
        return 0 # Domain is valid
    else
        log_message "ERROR: Cannot resolve domain: $hostname"
        echo "Error: Cannot resolve domain: $hostname"
        return 1 # Domain is invalid
    fi
}

# Function to check TLS version of a domain ("tls1" "tls1_1" "tls1_2" "tls1_3")
TLS_VERSIONS=("tls1" "tls1_1" "tls1_2" "tls1_3")
check_tls_version() {
    local domain=$1

    # First validate the domain
    if ! validate_domain "$domain"; then
        log_message "Skipping TLS check for invalid domain: $domain"
        echo "Skipping TLS check for invalid domain: $domain"
        echo "-------------------------------------"
        return 1
    fi

    # Parse HOST and PORT from domain parameter
    HOST=${domain%:*}
    PORT=${domain#*:}
    # If no port specified, default to 443
    if [ "$PORT" = "$HOST" ]; then
        PORT=443
    fi
    echo "Checking TLS version for: $domain"
for version in "${TLS_VERSIONS[@]}"; do
    echo | openssl s_client -connect "${HOST}:${PORT}" -${version} 2>&1 | grep -q "no protocols available"
    if [ $? -eq 1 ]; then
        log_message "TLS version ${version} is supported on ${HOST}:${PORT}"
        echo "  TLS version ${version} is supported on ${HOST}:${PORT}"
    else
        log_message "TLS version ${version} is NOT supported on ${HOST}:${PORT}"
        echo "  TLS version ${version} is NOT supported on ${HOST}:${PORT}"
    fi

done
echo "-------------------------------------"
}

# Main logic
if [ $# -eq 1 ] && [ -f "$1" ]; then
    # If a single argument is provided and it's a file, process the file
    filename=$1
    echo "Reading domains from file: $filename"
    log_message "Starting TLS checks for domains from file: $filename"
    while IFS= read -r domain; do
        if [ -n "$domain" ]; then
            check_tls_version "$domain"
        fi
    done < "$filename"
elif [ $# -eq 1 ]; then
    # If a single argument is provided and it's not a file, treat it as a domain
    domain=$1
    check_tls_version "$domain"
elif [ $# -gt 1 ]; then
    # If multiple arguments are provided, process them as domains
    echo "Processing provided arguments as domains..."
    for domain in "$@"; do
        check_tls_version "$domain"
    done
else
    # No arguments or file provided
    log_message "Script executed without required arguments"
    echo "Usage:"
    echo "  $0 endpoints.txt                        # To check TLS versions for domains in a file"
    echo "  $0 domain.com:port                      # To check TLS versions for a single domain"
    echo "  $0 domain1.com:port  domain2.com:port   # To check TLS versions for multiple domains"
    exit 1
fi
