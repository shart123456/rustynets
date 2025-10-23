# RustyNets - Comprehensive Network Security Toolkit

A high-performance network security tool built with Rust and exposed to Python via PyO3. Features HTTP/HTTPS analysis, brute force attacks, SQL injection detection, XSS scanning, web fuzzing, and DNS operations.

## ⚠️ Legal Disclaimer

**AUTHORIZED USE ONLY**: This tool is designed for security professionals, penetration testers, and authorized security assessments. Only use this tool on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal.

---

## 🚀 Features

### 🔒 HTTP Security Scanner
- Missing security headers detection (HSTS, CSP, X-Frame-Options, etc.)
- Insecure configuration detection
- Protocol vulnerability detection
- Redirect chain analysis
- Risk scoring (0-100)

### 💥 Brute Force Module
- HTTP authentication brute forcing
- Support for GET and POST methods
- Multiple detection modes (length, text, status)
- Cookie-based authentication support
- Configurable workers and delays
- Custom success/failure indicators

### 🗄️ SQL Injection Scanner
- Automated SQLi vulnerability detection
- Support for multiple database types (MySQL, PostgreSQL, Oracle, MSSQL)
- Time-based blind SQLi detection
- Boolean-based blind SQLi detection
- Error-based SQLi detection
- Out-of-band (OOB) testing support
- Configurable payload files
- Statistical validation for time-based attacks
- Rate limiting and request throttling

### 🔗 XSS Scanner
- Reflected XSS detection
- Stored XSS detection (optional)
- DOM-based XSS detection (optional)
- Context-aware payload generation
- Multiple encoding techniques
- Cookie-based authentication

### 🔍 Web Fuzzer
- Directory/file fuzzing
- Subdomain enumeration
- Parameter discovery
- File extension fuzzing
- Recursive fuzzing support
- Custom 404 detection (baseline)
- Status code filtering
- High-speed concurrent requests

### 🌐 DNS Operations
- DNS resolution (A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV, CAA)
- Reverse DNS lookups
- Custom nameserver support
- Dig-like functionality
- Query all record types

---

## 📦 Installation

### Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Verify installation
rustc --version
cargo --version

# Install Python development headers (for Python bindings)
# Ubuntu/Debian:
sudo apt-get install python3-dev

# macOS:
brew install python3
```

### Build from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/rustynets.git
cd rustynets

# Build in release mode (optimized)
cargo build --release

# The binary will be at: ./target/release/netool
./target/release/netool --help
```

### Install as System Tool

```bash
# Option 1: Install using cargo
cargo install --path .

# Option 2: Copy to system path
sudo cp target/release/netool /usr/local/bin/
sudo chmod +x /usr/local/bin/netool

# Verify installation
netool --version
```

---

## 🛠️ Usage

### General Syntax

```bash
# Using cargo (during development)
cargo run -- <command> [options]

# Using compiled binary
./target/release/netool <command> [options]

# If installed system-wide
netool <command> [options]
```

---

## 📖 Module Documentation

### 1️⃣ HTTP Security Scanner

Analyze HTTP security headers and detect vulnerabilities.

#### Basic Usage
```bash
# Scan a single URL
cargo run -- scan --url https://example.com

# Disable redirect following
cargo run -- scan --url https://example.com --no-redirects

# Set custom timeout
cargo run -- scan --url https://example.com --timeout 30

# JSON output
cargo run -- scan --url https://example.com --output json
```

#### Batch Scanning
```bash
# Create URL list
cat > urls.txt << EOF
https://example.com
https://google.com
https://github.com
EOF

# Scan multiple URLs
cargo run -- batch --file urls.txt --workers 10
```

---

### 2️⃣ Brute Force Module

**⚠️ AUTHORIZED USE ONLY**

Perform brute force attacks against HTTP authentication.

#### Basic Brute Force Attack
```bash
# GET request brute force
cargo run -- bruteforce \
  --url "http://testsite.com/login" \
  --usernames users.txt \
  --passwords passwords.txt \
  --workers 50

# POST request brute force
cargo run -- bruteforce \
  --url "http://testsite.com/login" \
  --usernames users.txt \
  --passwords passwords.txt \
  --method POST \
  --workers 50
```

#### Advanced Options
```bash
# With cookies (for authenticated sessions)
cargo run -- bruteforce \
  --url "http://dvwa.local/vulnerabilities/brute/" \
  --usernames users.txt \
  --passwords passwords.txt \
  --cookies "PHPSESSID=abc123; security=low" \
  --method GET \
  --workers 30

# Custom detection (text-based)
cargo run -- bruteforce \
  --url "http://target.com/login" \
  --usernames users.txt \
  --passwords passwords.txt \
  --detection text \
  --success-text "Welcome" \
  --failure-text "Invalid credentials" \
  --workers 20 \
  --delay 100

# Status code detection
cargo run -- bruteforce \
  --url "http://target.com/login" \
  --usernames users.txt \
  --passwords passwords.txt \
  --detection status \
  --workers 50
```

#### Detection Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `length` | Detects based on response size | Most reliable for GET requests |
| `text` | Looks for specific success/failure text | Customizable indicators |
| `status` | Detects based on HTTP status codes | Simple login pages |

#### Creating Wordlists
```bash
# Simple username list
cat > users.txt << EOF
admin
user
test
root
administrator
EOF

# Use common password lists
# Download rockyou.txt or use custom passwords
cat > passwords.txt << EOF
password
123456
admin
letmein
password123
EOF
```

---

### 3️⃣ SQL Injection Scanner

**⚠️ AUTHORIZED USE ONLY**

Automated SQL injection vulnerability detection.

#### Basic SQLi Scan
```bash
# Scan a URL for SQL injection
cargo run -- sqli-scan \
  --target "http://testsite.com/product?id=1" \
  --confirm-authorized

# With authentication token
cargo run -- sqli-scan \
  --target "http://testsite.com/search?q=test" \
  --confirm-authorized \
  --auth-token "proof-of-authorization-token"
```

#### Advanced SQLi Options
```bash
# Full scan with all options
cargo run -- sqli-scan \
  --target "http://testsite.com/page?id=1" \
  --confirm-authorized \
  --max-concurrency 5 \
  --rps 10 \
  --timeout 30 \
  --max-depth 3 \
  --time-delay 3 \
  --time-samples 5 \
  --output json

# With out-of-band testing
cargo run -- sqli-scan \
  --target "http://testsite.com/user?id=1" \
  --confirm-authorized \
  --enable-oob \
  --oob-host "your-callback-server.com"

# Custom payload file
cargo run -- sqli-scan \
  --target "http://testsite.com/page?id=1" \
  --confirm-authorized \
  --payload-file payloads/custom-sqli.yaml
```

#### SQLi Detection Techniques

The scanner tests for:
- **Error-based SQLi**: Forces database errors to appear in responses
- **Time-based blind SQLi**: Uses database sleep functions to confirm injection
- **Boolean-based blind SQLi**: Observes response differences based on true/false conditions
- **UNION-based SQLi**: Attempts to extract data using UNION queries
- **Out-of-band SQLi**: Uses DNS/HTTP callbacks for data exfiltration

#### Supported Databases
- MySQL/MariaDB
- PostgreSQL
- Oracle
- Microsoft SQL Server
- SQLite

#### Custom Payload Files

Create YAML files in `payloads/` directory:

```yaml
# payloads/custom-sqli.yaml
mysql:
  - payload: "' OR '1'='1"
    description: "Basic authentication bypass"
  - payload: "'; DROP TABLE users--"
    description: "Table deletion attempt"

postgresql:
  - payload: "' OR 1=1--"
    description: "Boolean-based injection"
```

---

### 4️⃣ XSS Scanner

**⚠️ AUTHORIZED USE ONLY**

Cross-Site Scripting vulnerability detection.

#### Basic XSS Scan
```bash
# Scan for reflected XSS
cargo run -- xss-scan \
  --target "http://testsite.com/search?q=test" \
  --confirm-authorized

# Test all XSS types
cargo run -- xss-scan \
  --target "http://testsite.com/comment?text=hello" \
  --confirm-authorized \
  --test-reflected true \
  --test-stored true \
  --test-dom true
```

#### Advanced XSS Options
```bash
# With authentication
cargo run -- xss-scan \
  --target "http://testsite.com/profile?name=user" \
  --confirm-authorized \
  --cookies "session=abc123; auth=xyz789" \
  --max-concurrency 10 \
  --timeout 30

# JSON output to file
cargo run -- xss-scan \
  --target "http://testsite.com/search" \
  --confirm-authorized \
  --output json \
  --output-file results/xss-scan.json

# YAML output
cargo run -- xss-scan \
  --target "http://testsite.com/page" \
  --confirm-authorized \
  --output yaml
```

#### XSS Payload Types

The scanner tests various contexts:
- HTML context: `<script>alert(1)</script>`
- Attribute context: `" onload="alert(1)"`
- JavaScript context: `'; alert(1);//`
- Event handlers: `<img src=x onerror="alert(1)">`
- URL context: `javascript:alert(1)`
- SVG context: `<svg onload="alert(1)">`

---

### 5️⃣ Web Fuzzer

High-speed web content discovery and fuzzing.

#### Directory Fuzzing
```bash
# Basic directory fuzzing
cargo run -- fuzz \
  --url https://example.com \
  --mode dir \
  --concurrent 50

# With custom wordlist
cargo run -- fuzz \
  --url https://example.com \
  --mode dir \
  --wordlist /path/to/custom-wordlist.txt \
  --concurrent 100

# Filter by status codes
cargo run -- fuzz \
  --url https://example.com \
  --mode dir \
  --status-filter "200,301,403" \
  --concurrent 50
```

#### Recursive Fuzzing
```bash
# Recursive directory discovery
cargo run -- fuzz \
  --url https://example.com \
  --mode dir \
  --recursive \
  --max-depth 3 \
  --concurrent 50

# Find config backups recursively
cargo run -- fuzz \
  --url https://example.com \
  --mode dir \
  --recursive \
  --max-depth 2 \
  --extensions ".bak,.old,.backup,.config" \
  --concurrent 30
```

#### File Extension Fuzzing
```bash
# Find PHP files
cargo run -- fuzz \
  --url https://example.com/admin \
  --mode extensions \
  --extensions ".php,.php3,.php4,.php5,.phtml" \
  --concurrent 50

# Find backup files
cargo run -- fuzz \
  --url https://example.com \
  --mode dir \
  --extensions ".bak,.old,.backup,.swp,.tmp" \
  --concurrent 50
```

#### Subdomain Enumeration
```bash
# Fuzz subdomains
cargo run -- fuzz \
  --url example.com \
  --mode subdomain \
  --concurrent 100 \
  --timeout 5

# With custom subdomain wordlist
cargo run -- fuzz \
  --url example.com \
  --mode subdomain \
  --wordlist subdomains.txt \
  --concurrent 150
```

#### Parameter Discovery
```bash
# Discover GET parameters
cargo run -- fuzz \
  --url https://example.com/page \
  --mode param \
  --concurrent 50

# Find hidden API parameters
cargo run -- fuzz \
  --url https://api.example.com/v1/users \
  --mode param \
  --wordlist api-params.txt \
  --concurrent 30
```

#### Advanced Fuzzing Options
```bash
# Complete fuzzing setup
cargo run -- fuzz \
  --url https://example.com \
  --mode dir \
  --wordlist /usr/share/wordlists/dirb/common.txt \
  --concurrent 100 \
  --status-filter "200,201,301,302,401,403" \
  --timeout 10 \
  --recursive \
  --max-depth 2 \
  --extensions ".php,.html,.asp,.aspx,.jsp" \
  --baseline true
```

#### Built-in Wordlists

The fuzzer includes built-in wordlists if none is provided:
- Common directories
- Common files
- Common subdomains
- API endpoints
- Admin panels

---

### 6️⃣ DNS Operations

DNS queries and domain information gathering.

#### DNS Resolution
```bash
# Resolve A records
cargo run -- dns --operation resolve --target example.com

# Batch DNS resolution
cat > domains.txt << EOF
google.com
github.com
example.com
EOF

cargo run -- dns --operation resolve --target domains.txt
```

#### Reverse DNS
```bash
# Reverse lookup single IP
cargo run -- dns --operation reverse --target 8.8.8.8

# Batch reverse lookup
cat > ips.txt << EOF
8.8.8.8
1.1.1.1
8.8.4.4
EOF

cargo run -- dns --operation reverse --target ips.txt
```

#### Advanced DNS (Dig)
```bash
# Query A records
cargo run -- dig --domain example.com --record-type A

# Query MX records
cargo run -- dig --domain example.com --record-type MX

# Query TXT records
cargo run -- dig --domain example.com --record-type TXT

# Query all record types
cargo run -- dig --domain example.com --all

# Use custom nameserver
cargo run -- dig \
  --domain example.com \
  --record-type A \
  --nameserver 8.8.8.8

# Short output (answers only)
cargo run -- dig --domain example.com --record-type A --short
```

#### Supported Record Types
- `A` - IPv4 addresses
- `AAAA` - IPv6 addresses
- `MX` - Mail exchange
- `NS` - Name servers
- `TXT` - Text records
- `CNAME` - Canonical name
- `SOA` - Start of authority
- `PTR` - Pointer (reverse DNS)
- `SRV` - Service records
- `CAA` - Certificate authority authorization
- `ANY` - All records

---

## 🐍 Python API

### Installation
```bash
# Install maturin
pip install maturin

# Build and install Python module
maturin develop --release
```

### HTTP Security Scanning
```python
import asyncio
import netool

async def scan_website():
    result = await netool.http_get_secure(
        "https://example.com",
        follow_redirects=True,
        max_redirects=10,
        timeout=30,
        analyze_security=True
    )
    
    if result['success']:
        print(f"Risk Score: {result['security_analysis']['risk_score']}/100")
        print(f"Status: {result['status']}")
        for vuln in result['security_analysis']['vulnerabilities']:
            print(f"- {vuln}")

asyncio.run(scan_website())
```

### Batch Scanning
```python
import asyncio
import netool

async def batch_scan():
    urls = [
        "https://example.com",
        "https://google.com",
        "https://github.com",
    ]
    
    tasks = [
        netool.http_get_secure(url, analyze_security=True) 
        for url in urls
    ]
    results = await asyncio.gather(*tasks)
    
    for result in results:
        if result['success']:
            risk = result['security_analysis']['risk_score']
            print(f"{result['url']}: Risk {risk}/100")

asyncio.run(batch_scan())
```

---

## 📊 Risk Scoring System

### HTTP Security Risk Score

| Score Range | Risk Level | Description |
|-------------|-----------|-------------|
| 0           | Secure    | No issues detected |
| 1-14        | Low       | Minor issues |
| 15-29       | Medium    | Several issues |
| 30-49       | High      | Significant concerns |
| 50+         | Critical  | Severe vulnerabilities |

### Score Calculation

#### Missing Headers
- `strict-transport-security`: +15 points
- `content-security-policy`: +15 points
- `x-frame-options`: +10 points
- `x-content-type-options`: +8 points
- `permissions-policy`: +8 points
- `referrer-policy`: +5 points
- `x-xss-protection`: +5 points

#### Vulnerabilities
- HTTPS to HTTP downgrade: +25 points
- HTTP usage: +20 points
- Cross-domain redirect: +10 points
- Debug header exposure: +8 points each
- Information disclosure: +5 points each

---

## 💡 Real-World Examples

### Example 1: Penetration Test Workflow

```bash
# 1. DNS reconnaissance
netool dig --domain target.com --all > recon/dns.txt

# 2. Subdomain enumeration
netool fuzz \
  --url target.com \
  --mode subdomain \
  --concurrent 100 > recon/subdomains.txt

# 3. Directory fuzzing
netool fuzz \
  --url https://target.com \
  --mode dir \
  --recursive \
  --max-depth 2 \
  --concurrent 50 > recon/directories.txt

# 4. Security header scan
netool scan --url https://target.com --output json > scan/headers.json

# 5. XSS scanning (authorized)
netool xss-scan \
  --target "https://target.com/search?q=test" \
  --confirm-authorized \
  --output json > scan/xss.json

# 6. SQLi scanning (authorized)
netool sqli-scan \
  --target "https://target.com/product?id=1" \
  --confirm-authorized \
  --output json > scan/sqli.json
```

### Example 2: Bug Bounty Hunting

```bash
#!/bin/bash
DOMAIN="target.com"

# Find subdomains
netool fuzz --url $DOMAIN --mode subdomain --concurrent 100 | \
  grep "200" | awk '{print $NF}' > subdomains.txt

# Scan each subdomain
while read subdomain; do
  echo "[*] Scanning $subdomain"
  
  # Security headers
  netool scan --url "https://$subdomain" --output json \
    > "results/${subdomain}-headers.json"
  
  # Directory fuzzing
  netool fuzz --url "https://$subdomain" --mode dir \
    --concurrent 50 --status-filter "200,403" \
    > "results/${subdomain}-dirs.txt"
done < subdomains.txt
```

### Example 3: Continuous Security Monitoring (Python)

```python
import asyncio
import netool
import json
from datetime import datetime

async def monitor_security():
    """Continuously monitor security posture"""
    
    urls = [
        "https://production.example.com",
        "https://api.example.com",
        "https://admin.example.com"
    ]
    
    while True:
        print(f"\n[*] Security Scan: {datetime.now()}")
        
        tasks = [
            netool.http_get_secure(url, analyze_security=True)
            for url in urls
        ]
        results = await asyncio.gather(*tasks)
        
        for result in results:
            if result['success']:
                risk = result['security_analysis']['risk_score']
                url = result['url']
                
                # Alert on high risk
                if risk >= 30:
                    print(f"🚨 ALERT: {url} - Risk Score: {risk}")
                    # Send notification (email, Slack, etc.)
                else:
                    print(f"✅ {url} - Risk Score: {risk}")
        
        # Wait 5 minutes
        await asyncio.sleep(300)

asyncio.run(monitor_security())
```

### Example 4: Automated Login Brute Force (DVWA Lab)

```bash
# Setup for DVWA (Damn Vulnerable Web Application)
# This is a LEGAL testing environment

# Create wordlists
echo "admin" > users.txt
cat > passwords.txt << EOF
password
admin
letmein
password123
123456
EOF

# Brute force DVWA login
netool bruteforce \
  --url "http://localhost/dvwa/vulnerabilities/brute/" \
  --usernames users.txt \
  --passwords passwords.txt \
  --cookies "PHPSESSID=your-session-id; security=low" \
  --method GET \
  --detection text \
  --success-text "Welcome to the password protected area" \
  --workers 20

# Expected output shows valid credentials when found
```

---

## ⚙️ Configuration Files

### SQLi Payload Configuration

Create custom payloads in `payloads/`:

```yaml
# payloads/mysql-payloads.yaml
mysql:
  - payload: "' OR '1'='1"
    type: "authentication_bypass"
    risk: "high"
  - payload: "' UNION SELECT NULL,NULL,NULL--"
    type: "union_based"
    risk: "critical"
  - payload: "' AND SLEEP(5)--"
    type: "time_based"
    risk: "medium"
```

### Fuzzing Wordlists

Built-in wordlists are included, but you can use custom ones:

```bash
# Use SecLists (popular wordlist collection)
git clone https://github.com/danielmiessler/SecLists.git

# Directory fuzzing with SecLists
netool fuzz \
  --url https://example.com \
  --mode dir \
  --wordlist SecLists/Discovery/Web-Content/common.txt
```

---

## 🔧 Development

### Project Structure

```
rustynets/
├── src/
│   ├── main.rs          # CLI entry point
│   ├── lib.rs           # Python bindings (PyO3)
│   ├── bruteforce.rs    # Brute force module
│   ├── sqli/           # SQL injection module
│   │   └── mod.rs
│   ├── xss.rs           # XSS scanner
│   ├── fuzz.rs          # Web fuzzer
│   ├── dig.rs           # DNS operations
│   ├── http.rs          # HTTP functionality
│   └── error.rs         # Error handling
├── payloads/           # Attack payloads
│   ├── mysql-payloads.yaml
│   ├── postgres-payloads.yaml
│   └── xss-payloads.txt
├── Sanity_Checks/      # Test scripts
├── Cargo.toml          # Rust dependencies
└── README.md
```

### Running Tests

```bash
# Run all tests
cargo test

# Run specific module tests
cargo test test_bruteforce

# Run with output
cargo test -- --nocapture
```

### Building

```bash
# Debug build (fast compilation)
cargo build

# Release build (optimized)
cargo build --release

# Check code without building
cargo check
```

### Code Quality

```bash
# Format code
cargo fmt

# Lint code
cargo clippy

# Run all checks
cargo fmt && cargo clippy && cargo test
```

---

## 🚀 Performance Optimization

### Tuning Concurrent Workers

```bash
# CPU-intensive: Match CPU cores
netool fuzz --url https://example.com --concurrent $(nproc)

# Network-intensive: Can go higher
netool fuzz --url https://example.com --concurrent 200

# Conservative (rate-limited sites)
netool fuzz --url https://example.com --concurrent 10
```

### Benchmarks

| Operation | Throughput | Notes |
|-----------|-----------|-------|
| HTTP scanning | ~100/sec | 10 workers |
| Directory fuzzing | ~500/sec | 50 workers |
| Subdomain enum | ~300/sec | 100 workers |
| Brute force | ~200/sec | 50 workers |
| SQLi scanning | ~10/sec | 5 workers (throttled) |

---

## 🐛 Troubleshooting

### Common Issues

#### 1. SSL/TLS Errors
```bash
# Some sites have certificate issues
# Currently validates certificates - modify source if testing needed
```

#### 2. Rate Limiting
```bash
# Reduce concurrent workers
netool fuzz --url https://target.com --concurrent 10

# Add delays (brute force)
netool bruteforce --url ... --delay 100
```

#### 3. Timeout Issues
```bash
# Increase timeout
netool scan --url https://slow-site.com --timeout 60
```

#### 4. Permission Denied
```bash
# Install to user directory instead
cargo install --path . --root ~/.local
export PATH="$HOME/.local/bin:$PATH"
```

---

## 📚 Additional Resources

### Learning Materials
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Bug Bounty Hunting Methodology](https://portswigger.net/burp/documentation)
- [SQL Injection Guide](https://portswigger.net/web-security/sql-injection)
- [XSS Tutorial](https://portswigger.net/web-security/cross-site-scripting)

### Testing Labs
- [DVWA](https://github.com/digininja/DVWA) - Damn Vulnerable Web Application
- [WebGoat](https://github.com/WebGoat/WebGoat) - OWASP Testing Lab
- [Juice Shop](https://github.com/juice-shop/juice-shop) - Modern vulnerable web app
- [HackTheBox](https://www.hackthebox.com/) - Penetration testing labs

### Wordlists & Payloads
- [SecLists](https://github.com/danielmiessler/SecLists) - Comprehensive wordlists
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - Payload collection
- [FuzzDB](https://github.com/fuzzdb-project/fuzzdb) - Attack patterns database

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

MIT License - see LICENSE file for details.

---

## 🔒 Security & Ethics

### Responsible Disclosure

If you discover vulnerabilities using this tool:
1. **Never** publicly disclose without permission
2. Contact the affected organization privately
3. Give them reasonable time to fix (90 days standard)
4. Follow responsible disclosure guidelines

### Legal Compliance

- ✅ Use on systems you own
- ✅ Use with written authorization
- ✅ Use in authorized bug bounty programs
- ✅ Use in sanctioned penetration tests
- ❌ **NEVER** use without permission
- ❌ **NEVER** use for illegal purposes

### Ethical Guidelines

This tool should be used to:
- Improve security posture
- Identify vulnerabilities for remediation
- Conduct authorized security assessments
- Learn about security in controlled environments

**NOT** to:
- Harm systems or networks
- Steal data or credentials
- Disrupt services
- Violate privacy or laws

---

## 🙏 Credits

Built with:
- [Rust](https://www.rust-lang.org/) - Systems programming language
- [Tokio](https://tokio.rs/) - Async runtime
- [reqwest](https://github.com/seanmonstar/reqwest) - HTTP client
- [PyO3](https://github.com/PyO3/pyo3) - Rust-Python bindings
- [clap](https://github.com/clap-rs/clap) - CLI argument parsing
- [hickory-dns](https://github.com/hickory-dns/hickory-dns) - DNS operations

---

## ⚠️ Final Warning

**This tool is powerful and can cause harm if misused.**

- Always get written authorization before testing
- Understand the legal implications in your jurisdiction
- Respect rate limits and system resources
- Follow ethical hacking guidelines
- When in doubt, DON'T

**Unauthorized access to computer systems is illegal and can result in criminal prosecution.**

---

**Happy (authorized) hacking! 🎯**
