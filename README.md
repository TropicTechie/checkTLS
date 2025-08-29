<img src="Padlock.png" width="200" height="200" alt="Padlock">

```
┌─┐┬ ┬┌─┐┌─┐┬┌─╔╦╗╦  ╔═╗
│  ├─┤├┤ │  ├┴┐ ║ ║  ╚═╗
└─┘┴ ┴└─┘└─┘┴ ┴ ╩ ╩═╝╚═╝
```

**Transport Layer Security** (TLS) is a cornerstone of modern cybersecurity, ensuring secure communication and protecting data from unauthorized access. For organizations, it is not just a technical necessity but a strategic tool for managing risk and maintaining compliance. By understanding and properly managing TLS, businesses can significantly enhance their overall security posture and reduce the likelihood of data breaches or regulatory penalties.

## Why is TLS critical for Risk Management and Security?

**Transport Layer Security (TLS)**, protects data in transit by encrypting communications between clients and services and provides confidentiality (preventing eavesdropping), integrity (detecting tampering), and authentication (verifying endpoints via certificates). Managing TLS correctly, enforcing modern protocol versions, robust cipher suites, and sound certificate lifecycle, directly reduces exploitable attack surface, audit findings, and operational outages tied to expired or misconfigured certificates.

Their importance in risk management and security can be summarized as follows:

- **Protect data in transit**: SSL/TLS encrypts traffic end-to-end, preventing eavesdropping and tampering (MITM) across public and private networks. Even internal traffic benefits from encryption to mitigate lateral movement risks.
- **Identity and trust**: Certificates bind identities (endpoints/services) to cryptographic keys. Proper validation (endpointname, chain, expiry, revocation) reduces impersonation risk and strengthens zero-trust postures.
- **Compliance and auditability**: Regulations and frameworks (PCI DSS, SOC 2) mandate strong encryption in transit. Enforcing modern TLS versions and approved cipher suites demonstrates due care and reduces audit findings.
- **Risk reduction through modernization**: Legacy SSL (SSLv2/SSLv3) and early TLS (1.0/1.1) are deprecated and vulnerable (e.g., POODLE, BEAST). Standardizing on TLS 1.2+ (preferably TLS 1.3) and vetted cipher suites meaningfully reduces attack surface.
- **Cryptographic agility**: Centralized policies for protocols, cipher suites, and key sizes allow fast response to newly disclosed weaknesses (e.g., deprecate RSA key exchange, disable CBC ciphers, adopt AEAD like GCM/ChaCha).
- **Operational resilience**: Robust certificate lifecycle management (issuance, rotation, expiry monitoring, revocation) prevents outages (expired certs) and reduces incident impact. Automating renewal and setting alarms well before expiry improves reliability.
- **Visibility and control**: Regular scanning/inventory of endpoints for protocol/cipher compliance, certificate ownership, SNI behavior, and mTLS coverage provides actionable telemetry for security and platform teams.
- **Defense-in-depth**: mTLS (mutual TLS) adds client authentication, limiting access to trusted workloads and hardening service-to-service communications in microservices and zero-trust architectures.
- **Performance with security**: TLS 1.3 delivers both stronger security and better performance (fewer round trips, modern cipher suites), reducing the perceived tradeoff between protection and user experience.

### Ports that support TLS

TLS is most commonly associated with **port 443 for HTTPS** _(secure web browsing)_, but its use extends well beyond the web. TLS secures email communication over port **465 for SMTPS** _(secure message submission)_, **port 993 for IMAPS** _(IMAP over TLS)_, and **port 995 for POP3S** _(POP3 over TLS)_. For secure file transfers, **FTPS** _(FTP over TLS)_ typically uses **ports 989 and 990**. Directory services like **LDAPS** operate over **port 636**, while secure **XMPP** traffic may use **port 5223**. TLS can also be negotiated dynamically using **STARTTLS** on ports like **25** _(SMTP)_, **143** _(IMAP)_, and **110** _(POP3)_, where an insecure connection is upgraded to a secure one.

Critically, TLS is not bound to specific ports, organizations can configure it on virtually any port, making it a flexible and powerful protocol for securing a wide range of network communications.

## Practical policy checklist

- Disable SSLv2/SSLv3 and TLS 1.0/1.1; allow only TLS 1.2+.
- Prefer `ECDHE` key exchange with `AEAD` ciphers (`TLS_AES_*_GCM_SHA256/384`, `CHACHA20-POLY1305`).
- Enforce certificate validation (chain/endpoint_name), track ownership, and rotate keys/certs regularly.
- Monitor days-to-expire, renewal success, and non-compliant endpoints.
- Use mTLS where appropriate for service-to-service and privileged access paths.

By transitioning to newer, more robust versions like TLS 1.2 and TLS 1.3, we benefit from stronger cryptographic algorithms, improved performance, and enhanced security features that address modern attack vectors. Updating TLS versions also ensures compliance with industry regulations and standards, which increasingly mandate the use of secure protocols.

> [!CAUTION]
> **Failure to stay current and implement best practices leaves systems exposed to known vulnerabilities, weak encryption, and non-compliance with security standards like PCI DSS, jeopardizing both the integrity of communications and the trust of clients and partners**.

## How to use

- Using this utility is simple, clone the repo to your computer:
```
git clone https://github.com/TropicTechie/checkTLS.git
```
- Add your endpoints and ports to the `endpoints.txt` file.
    * One line per endpoint, like this: `website.com:443` or `endpoint.domain.com:1234` or `000.000.000.000:1234`
- Run the script calling the file:
```
./checkTLS.sh endpoints.txt
```
- Alternatively, you can pass one or more `endpoint:port` arguments directly (no file needed):
```
./checkTLS.sh website.com:443 1.2.3.4:1234
./checkTLS.sh website.com:443 endpoint.domain.com:1234
```

## Results

You will see results like this:

```
./checkTLS.sh endpoints.txt
Checking TLS support for endpoint.domain.com:1234...
  TLS version tls1 is NOT supported on endpoint.domain.com:1234
  TLS version tls1_1 is NOT supported on endpoint.domain.com:1234
  TLS version tls1_2 is supported on endpoint.domain.com:1234
    cert cypher=ECDHE-RSA-AES128-GCM-SHA256
  TLS version tls1_3 is supported on endpoint.domain.com:1234
    cert cypher=TLS_AES_128_GCM_SHA256
-------------------------------------

Checking TLS support for endpoint.domain.com:0987...
  TLS version tls1 is NOT supported on endpoint.domain.com:0987
  TLS version tls1_1 is NOT supported on endpoint.domain.com:0987
  TLS version tls1_2 is supported on endpoint.domain.com:0987
    cert cypher=ECDHE-RSA-CHACHA20-POLY1305
  TLS version tls1_3 is supported on endpoint.domain.com:0987
    cert cypher=TLS_AES_128_GCM_SHA256
-------------------------------------
```

If an endpoint cannot be resolved, you will see this:

```
Error: Cannot resolve endpoint: endpoint.domain.com
Skipping checks for invalid endpoint: endpoint.domain:443
-------------------------------------
```

## Command-line options

Below are all supported options, what they do, and an example of each in use.

- Input modes:
    - File mode: `./checkTLS.sh endpoints.txt` where the file contains one `endpoint:port` per line
    - Direct args mode: `./checkTLS.sh endpoint.domain:1234 endpoint.domain:1234 ...`

- `-t`, `--timeout SECONDS`
    - What it does: Sets a per-connection timeout (in seconds) for each OpenSSL attempt. Default is 5 seconds.
    - Why use it: Avoid long hangs on unresponsive endpoints/ports.
    - Example: `./checkTLS.sh -t 3 endpoints.txt`

- `-f`, `--format FORMAT`
    - What it does: Controls output format: `text` (default), `json`, or `csv`.
    - Why use it: `json`/`csv` are convenient for scripting/automation; `text` is human-friendly.
    - Examples:
        - Text: `./checkTLS.sh -f text endpoints.txt`
        - JSON: `./checkTLS.sh -f json endpoints.txt | jq '{endpoint,port,version,status,protocol,cipher}'`
        - CSV: `./checkTLS.sh -f csv endpoints.txt`

- `--no-sni`
    - What it does: Disables SNI (Server Name Indication) in TLS handshake.
    - Why use it: Some servers behave differently or fail when SNI is not provided; useful for diagnostics.
    - Example: `./checkTLS.sh --no-sni endpoints.txt`

- `--cert-info`
    - What it does: Prints certificate subject, issuer, and validity dates for supported handshakes.
    - Why use it: Inspect presented certificates alongside protocol/cipher.
    - Examples:
        - Text: `./checkTLS.sh --cert-info endpoints.txt`
        - JSON: `./checkTLS.sh -f json --cert-info endpoints.txt | jq -r 'select(.status=="SUPPORTED") | {endpoint,version,protocol,cipher,cert_info}'`

- `-j`, `--jobs N`
    - What it does: Checks up to N endpoints concurrently. Default is 1.
    - Why use it: Speed up checks across larger endpoint lists.
    - Examples:
        - Serial: `./checkTLS.sh -j 1 endpoints.txt`
        - Parallel: `./checkTLS.sh -j 4 endpoints.txt`

- `-h`, `--help`
    - What it does: Displays inline usage information and exits.
    - Example: `./checkTLS.sh -h`

> [!NOTE]
>
> - Protocol and cipher are always shown for supported connections in all formats.
> - Input file format is one `endpoint:port` per line.
>     - Blank lines and `#` comments are ignored.
>     - Duplicate entries are deduplicated.
> - By default, SNI is enabled and the `servername` used is the endpoint from each `endpoint:port` line.

### Advanced usage and flags

The script supports several flags to control output, connection behavior, and performance.

> [!NOTE]
>
> - For supported handshakes, text output shows the negotiated cipher as “`cert cypher=…`”.
> - JSON and CSV include both protocol and cipher fields for automation.

- **Output format**
    - text (default): human-friendly output (shows “`cert cypher=...`” under supported versions)
        - Example: `./checkTLS.sh -f text endpoints.txt`
    - json: one JSON object per line; includes fields protocol and cipher (and cert_info when requested)
        - Example: `./checkTLS.sh -f json endpoints.txt | jq '{endpoint,port,version,status,protocol,cipher}'`
    - csv: comma-separated with header; columns: endpoint,port,version,status,protocol,cipher
        - Example: `./checkTLS.sh -f csv endpoints.txt`
        - Create a CS File: `./checkTLS.sh -f csv endpoints.txt > export.csv`
- **SNI control**
    - SNI enabled by default (uses `-servername <endpoint>` during TLS handshake)
        - Example: `./checkTLS.sh endpoints.txt`
    - Disable SNI with `--no-sni`
    - Example: `./checkTLS.sh --no-sni endpoints.txt`
- **Certificate info**
    - Include certificate details with `--cert-info` (only shown for supported versions). In text output, this prints:
        - subject: the Common Name (CN) only
        - issuer: the Organization (O) if present, otherwise the issuer CN, with extra characters removed
        - days_to_expire: computed from the certificate’s notAfter date
    - Protocol/cipher are included or derivable regardless of this flag (text shows cipher; JSON/CSV include both fields).
    - Examples:
        - Text: `./checkTLS.sh --cert-info endpoints.txt`
        - JSON: `./checkTLS.sh -f json --cert-info endpoints.txt | jq -r 'select(.status=="SUPPORTED") | {endpoint,version,protocol,cipher,cert_info}'`
- **Timeout**
    - Set per-connection timeout (seconds) with `-t`/`--timeout` (default: 5)
    - Example: `./checkTLS.sh -t 3 endpoints.txt`
- **Concurrency**
    - Number of endpoints to check in parallel with `-j`/`--jobs` (default: 1)
    - Example: `./checkTLS.sh -j 4 endpoints.txt`

### Combined examples

- Fast, structured output for automation:
  - `./checkTLS.sh -t 3 -j 4 -f json endpoints.txt`
- Human-readable with certificate details:
  - `./checkTLS.sh --cert-info endpoints.txt`
- Diagnose SNI dependence:
  - `./checkTLS.sh endpoints.txt`
  - `./checkTLS.sh --no-sni endpoints.txt`

## Example Outputs

- Running `./checkTLS.sh --cert-info endpoints.txt`:
```
Checking TLS support for website.com:443...
  TLS version tls1 is NOT supported on website.com:443
  TLS version tls1_1 is NOT supported on website.com:443
  TLS version tls1_2 is supported on website.com:443
    cert cypher=ECDHE-RSA-AES128-GCM-SHA256
    subject=www.website.com
    issuer=IssuerName.com
    days_to_expire=311
  TLS version tls1_3 is NOT supported on website.com:443
```
- Running `./checkTLS.sh -f json endpoints.txt | jq '{endpoint,port,version,status,protocol,cipher}'`:
```
{
  "endpoint": "endpoint.domain.com",
  "port": 3389,
  "version": "tls1",
  "status": "NOT_SUPPORTED",
  "protocol": null,
  "cipher": null
}
{
  "endpoint": "website.com",
  "port": 443,
  "version": "tls1_2",
  "status": "SUPPORTED",
  "protocol": "TLSv1.2",
  "cipher": "ECDHE-RSA-AES128-GCM-SHA256"
}
```
