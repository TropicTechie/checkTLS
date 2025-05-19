<img src="Padlock.png" width="200" height="200" alt="Padlock">

**Transport Layer Security** (TLS) is a cornerstone of modern cybersecurity, ensuring secure communication and protecting data from unauthorized access. For organizations, it is not just a technical necessity but a strategic tool for managing risk and maintaining compliance. By understanding and properly managing TLS, businesses can significantly enhance their overall security posture and reduce the likelihood of data breaches or regulatory penalties.

## Why is TLS Important in Risk Management and Security?

TLS plays a critical role in safeguarding sensitive data and maintaining trust in digital communications. Its importance in risk management and security can be summarized as follows:

1. **Mitigates Risk of Data Breaches**: TLS encrypts sensitive data such as credentials, financial information, and PII, significantly reducing the risk of interception and unauthorized disclosure. Legacy versions leave data vulnerable to known exploits.
2. **Prevents Man-in-the-Middle (MITM) Attacks**: Modern TLS protocols provide mutual authentication and secure key exchange, making it far more difficult for attackers to impersonate trusted parties or alter communications undetected.
3. **Enables Regulatory Compliance**: Frameworks such as PCI DSS, HIPAA, SOX, and GDPR mandate the use of secure, up-to-date encryption protocols. Operating with outdated TLS versions (e.g., TLS 1.0 or 1.1) can result in compliance violations and financial penalties.
4. **Strengthens Business Resilience**: Cyber incidents involving unencrypted or poorly encrypted data can lead to operational disruptions, brand damage, and costly litigation. TLS reduces this risk by hardening one of the most common attack surfaces—data in transit.
5. **Supports Third-Party Risk Management**: Demonstrating strong encryption practices, including current TLS implementation, assures partners and customers that your organization meets industry-standard security expectations.

By transitioning to newer, more robust versions like TLS 1.2 and TLS 1.3, organizations benefit from stronger cryptographic algorithms, improved performance, and enhanced security features that address modern attack vectors. Updating TLS versions also ensures compliance with industry regulations and standards, which increasingly mandate the use of secure protocols.

> [!CAUTION]
> Failing to stay current with TLS versions exposes your systems to known vulnerabilities, weak encryption, and non-compliance with security standards like PCI DSS. **Jeopardizing both the integrity of communications and the trust of clients and partners**. Always use supported, modern TLS versions (e.g., TLS 1.2 or higher) to protect data in transit and maintain secure communication.

## How to use

Using this utility is simple, clone the repo to your computer then use one of the options below. This script can be used on hosts, ips and sites. If a port is not specified, it will default to `443`.

- `hostname.domain.com:port`
- `192.168.10.124:port`
- `sitename.com:port`

#### Ports that support TLS

TLS is most commonly associated with **port 443 for HTTPS** _(secure web browsing)_, but its use extends well beyond the web. TLS secures email communication over port **465 for SMTPS** _(secure message submission)_, port **993 for IMAPS** _(IMAP over TLS)_, and port **995 for POP3S** _(POP3 over TLS)_. For secure file transfers, **FTPS** _(FTP over TLS)_ typically uses ports **989** and **990**. Directory services like **LDAPS** operate over port **636**, while secure **XMPP** traffic may use port **5223**. TLS can also be negotiated dynamically using **STARTTLS** on ports like **25 (SMTP)**, **143 (IMAP)**, and **110 (POP3)**, where an insecure connection is upgraded to a secure one. Critically, TLS is not bound to specific ports—organizations can configure it on virtually any port, making it a flexible and powerful protocol for securing a wide range of network communications.

### Clone the repo:

```
git clone https://github.com/TropicTechie/checkTLS.git
```

#### Option 1

Use this option when you have one or a few endpoints to verify.

- To check TLS versions for a single domain:
```
./checkTLS.sh domain.com:1234
```
- To check TLS versions for multiple endpoints:
```
./checkTLS.sh sitename.com:1234 sitename.com:1234
```

#### Option 2

Using the `endpoints.txt` file when you have lots of endpoints to check.

- Add your hosts and ports to the `endpoints.txt` file.
    - One line per host or ip address, like this:
        - `hostname.domain.com:1234`
        - `000.000.000.000:1234`
        - `domain.com:1234`
- To check TLS versions for endpoints in a file
```
./checkTLS.sh endpoints.txt
```

## Results

You should see results like this:

```
Processing provided arguments as domains...
Checking TLS version for: sitename.com:443
 TLS version tls1 is NOT supported on sitename.com:443
 TLS version tls1_1 is NOT supported on sitename.com:443
 TLS version tls1_2 is supported on sitename.com:443
 TLS version tls1_3 is supported on sitename.com:443
-------------------------------------
Error: Cannot resolve domain: sitename1.com
Skipping TLS check for invalid domain: sitename1.com:443
-------------------------------------
```
