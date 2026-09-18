# 🇧🇩 BD-OSINT v3

<p align="center">
  <img src="./assets/bdsont.png" alt="BD-OSINT v3 — Bangladesh-focused OSINT & Defensive Reconnaissance" width="100%">
</p>


### Bangladesh-Focused OSINT & Defensive Attack-Surface Discovery Framework

> **Collect • Analyze • Report • Defend**

BD-OSINT is a Bangladesh-focused **Open Source Intelligence (OSINT)** and defensive reconnaissance framework designed to collect publicly available information about domains and internet-facing assets.

It combines passive intelligence sources such as DNS, RDAP, Certificate Transparency, historical URLs, TLS certificates, HTTP metadata, security.txt, and technology detection into structured, evidence-based reports.

The project is designed with **scope enforcement, conservative rate limiting, automatic redaction, evidence-based findings, and authorization controls** as core safety principles.

---

## ✨ Highlights

| Capability                   | Description                                                                  |
| ---------------------------- | ---------------------------------------------------------------------------- |
| 🌐 Passive OSINT             | Collect publicly available domain and infrastructure metadata                |
| 🇧🇩 Bangladesh Intelligence | Bangladesh-specific TLD and domain classification                            |
| 🔎 Attack-Surface Discovery  | Identify subdomains, technologies, historical endpoints and exposed metadata |
| 🛡️ Defensive Analysis       | Evidence-based observations instead of automatic vulnerability claims        |
| 📊 Reporting                 | JSON, CSV, HTML dashboard and relationship graph output                      |
| 🚦 Scope Control             | Prevent collection outside the supplied target scope                         |
| ⚡ Rate Limiting              | Per-provider and Bangladesh-sensitive rate controls                          |
| 🔐 Redaction                 | Automatically redact token, password and secret-like values                  |
| 🧪 Testing                   | Structured automated test suite                                              |
| 🔒 Authorized Scanning       | Active checks are explicitly gated behind authorization                      |

---

# 📌 What BD-OSINT Does

BD-OSINT takes a domain within an explicitly defined scope and builds a structured intelligence picture from multiple public sources.

Typical workflow:

```text
                    ┌────────────────────┐
                    │      TARGET        │
                    │   example.com.bd   │
                    └─────────┬──────────┘
                              │
                              ▼
                  ┌───────────────────────┐
                  │    Scope Validation   │
                  └───────────┬───────────┘
                              │
             ┌────────────────┼────────────────┐
             ▼                ▼                ▼
        DNS / RDAP       Certificate       Wayback
                           Transparency
             │                │                │
             └────────────────┼────────────────┘
                              ▼
                    ┌──────────────────┐
                    │ Metadata Analysis│
                    ├──────────────────┤
                    │ Headers          │
                    │ Technologies     │
                    │ Subdomains       │
                    │ TLS              │
                    │ security.txt     │
                    └────────┬─────────┘
                             │
                             ▼
                   ┌────────────────────┐
                   │ Findings Engine    │
                   │ observed           │
                   │ potential          │
                   │ verified           │
                   └─────────┬──────────┘
                             │
                             ▼
                 ┌────────────────────────┐
                 │ JSON / CSV / HTML /    │
                 │ Relationship Graph     │
                 └────────────────────────┘
```

---

# 🚀 Features

## 🌐 Passive Intelligence Modules

BD-OSINT currently supports:

* `dns` — DNS information
* `rdap` — Registration and allocation data
* `crtsh` — Certificate Transparency discovery
* `wayback` — Historical URLs
* `tls` — TLS certificate metadata
* `headers` — HTTP security and response headers
* `tech` — Technology identification
* `securitytxt` — security.txt discovery
* `http` — Public HTTP metadata
* `subdomains` — Subdomain analysis

Passive collection is designed to rely on publicly available information and controlled HTTP requests.

---

## 🇧🇩 Bangladesh Intelligence

BD-OSINT includes Bangladesh-specific logic for domains and organizations.

Supported categories include:

```text
.gov.bd
.edu.bd
.ac.bd
.com.bd
.org.bd
.net.bd
```

The framework can use Bangladesh-specific domain rules to provide additional context during analysis.

Sensitive institutional categories such as:

```text
.gov.bd
.edu.bd
.ac.bd
```

receive conservative rate-limiting behavior.

---

# 🛡️ Security & Safety Model

Safety is a core design requirement of BD-OSINT.

### Passive by Default

Normal reconnaissance focuses on publicly available information.

The framework does **not** perform:

* Credential theft
* Phishing
* Password attacks
* Brute-force authentication
* Authentication bypass
* Exploitation
* WAF/CAPTCHA evasion
* Private citizen-data lookup
* NID database searching
* Phone location tracking
* Call-record collection

---

## 🔐 Authorized Active Scanning

Active functionality is intentionally separated from passive collection.

Available authorized modules include:

```text
ports
axfr
```

These are disabled by default and require:

```text
--profile authorized
```

You should only use active scanning against systems for which you have documented authorization.

---

# 🔎 Evidence-Based Findings

BD-OSINT intentionally avoids treating every unusual observation as a vulnerability.

Findings use three primary statuses:

```text
observed
potential
verified
```

For example:

```text
Missing security header
        ↓
Observed configuration
        ↓
Not automatically classified as
a security vulnerability
```

This approach helps reduce false positives and keeps reports focused on evidence.

---

# 📊 Reporting

BD-OSINT can produce structured reports in multiple formats:

```text
JSON
CSV
HTML
Relationship Graph
```

### JSON

Useful for:

* Automation
* SIEM pipelines
* Further analysis
* Programmatic processing

### CSV

Useful for:

* Spreadsheets
* Investigation workflows
* Data filtering
* Evidence review

### HTML

Provides a human-readable report/dashboard for investigation and documentation.

### Relationship Graph

Visualizes relationships between discovered entities and collected information.

---

# ⚙️ Installation

## Requirements

Recommended environment:

```text
Python 3
pip
Git
```

Optional dependencies for additional functionality:

```text
Graphviz
Nmap
```

---

## Option 1 — Automated Setup

```bash
git clone https://github.com/blackhelixunit/bd-osint.git
cd bd-osint

bash setup.sh
```

---

## Option 2 — Manual Python Environment

```bash
git clone https://github.com/blackhelixunit/bd-osint.git
cd bd-osint

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

Optional system packages:

```bash
sudo apt install graphviz nmap
```

---

# 🖥️ Usage

Display the command-line help:

```bash
python3 bdosint.py --help
```

Basic structure:

```bash
python3 bdosint.py [OPTIONS] TARGET
```

Example:

```bash
python3 bdosint.py example.com.bd
```

Specify modules:

```bash
python3 bdosint.py \
  --modules dns,rdap,crtsh,wayback,tls,headers,tech \
  example.com.bd
```

Generate a report:

```bash
python3 bdosint.py \
  --modules dns,rdap,crtsh,wayback,tls,headers,tech \
  --format html \
  example.com.bd
```

---

# 🔒 Authorized Profile

Active functionality should only be used when you have permission to test the target.

Example:

```bash
python3 bdosint.py \
  --profile authorized \
  --modules ports \
  example.com.bd
```

For DNS zone-transfer testing:

```bash
python3 bdosint.py \
  --profile authorized \
  --modules axfr \
  example.com.bd
```

> **Important:** Authorization belongs to the operator. Always obtain documented permission before performing active security testing.

---

# 📁 Project Structure

```text
bd-osint/
│
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── pyproject.toml
├── requirements.txt
├── config.yaml
├── setup.sh
├── bdosint.py
│
├── bdosint/
│   ├── __init__.py
│   ├── cli.py
│   ├── models.py
│   ├── scope.py
│   ├── config.py
│   ├── logging_utils.py
│   │
│   ├── analysis/
│   │   ├── relationships.py
│   │   ├── findings.py
│   │   ├── subdomains.py
│   │   ├── headers.py
│   │   └── technologies.py
│   │
│   ├── bangladesh/
│   │   ├── tld.py
│   │   └── domain_rules.py
│   │
│   ├── core/
│   │   ├── normalization.py
│   │   ├── cache.py
│   │   ├── rate_limiter.py
│   │   └── http.py
│   │
│   ├── passive/
│   │   ├── dns.py
│   │   ├── rdap.py
│   │   ├── wayback.py
│   │   ├── crtsh.py
│   │   ├── certificates.py
│   │   ├── http_metadata.py
│   │   ├── securitytxt.py
│   │   └── shodan_optional.py
│   │
│   └── authorized/
│       ├── nmap_scan.py
│       └── active_checks.py
│
└── tests/
```

---

# 🧠 Architecture Principles

BD-OSINT follows several design principles:

### 1. Scope First

The framework should never expand beyond the supplied target scope.

### 2. Passive First

Public intelligence collection is preferred before active checks.

### 3. Evidence Before Claims

Collected information should be distinguishable from analytical interpretation.

### 4. Conservative Classification

Interesting data is not automatically considered a vulnerability.

### 5. Automatic Redaction

Potentially sensitive token/password/secret patterns are redacted from reports.

### 6. Controlled Active Testing

Active modules require an explicit authorized profile.

---

# 🚦 Rate Limiting & Caching

BD-OSINT includes:

* Per-provider rate limiting
* Filesystem TTL caching
* Conservative Bangladesh-specific controls
* Controlled HTTP requests
* Scope validation

These mechanisms are intended to reduce unnecessary traffic and make investigations more predictable and responsible.

---

# 🧪 Testing

The project includes automated tests covering areas such as:

```text
Normalization
Scope enforcement
DNS
RDAP
Certificates
Headers
Technologies
Findings
Caching
Redaction
Bangladesh TLD logic
```

Run the test suite with:

```bash
pytest
```

---

# 📚 Public Data Sources

BD-OSINT is designed around publicly accessible intelligence sources, including categories such as:

* DNS infrastructure
* RDAP registration information
* Certificate Transparency
* Historical web archives
* Public TLS metadata
* Public HTTP response metadata
* security.txt
* Public technology fingerprints

The availability and behavior of external providers may change over time.

---

# ⚠️ Limitations

BD-OSINT is an intelligence-gathering and defensive reconnaissance framework.

It does **not** guarantee:

* Complete asset discovery
* Complete historical URL discovery
* Vulnerability detection
* Accuracy of third-party data
* Availability of external providers
* Verification of ownership from public metadata alone

Results should therefore be independently reviewed before being used for security decisions.

---

# 🤝 Contributing

Contributions are welcome.

Before contributing, please read:

```text
CONTRIBUTING.md
```

Areas where contributions may be useful include:

* New passive data providers
* Bangladesh-specific domain intelligence
* Detection improvements
* Report formatting
* Test coverage
* Documentation
* Performance improvements
* False-positive reduction

Security and safety invariants should not be weakened.

---

# 🗺️ Roadmap

Potential future improvements:

```text
[ ] Additional Bangladesh public-data sources
[ ] Improved relationship visualization
[ ] More passive discovery providers
[ ] Expanded test coverage
[ ] Improved HTML reporting
[ ] Additional technology fingerprints
[ ] Better provider failure handling
[ ] Additional export formats
```

---

# ⚖️ Ethics & Legal Notice

BD-OSINT is intended for:

* Authorized security research
* Defensive reconnaissance
* OSINT investigations
* Security assessments with permission
* Academic and educational research
* Attack-surface documentation

Do not use this project to access, collect, or test systems or data without appropriate authorization.

The user of this software is responsible for complying with applicable laws, regulations, terms of service, and organizational policies.

---

# 📜 License

This project is released under the **MIT License**.

See:

```text
LICENSE
```

for the complete license text.

---

# 🇧🇩 About

**BD-OSINT v3** is built around a simple idea:

> **Better information. Safer decisions.**

Designed for Bangladesh-focused OSINT, defensive reconnaissance, security research, and responsible digital investigations.

### Collect • Analyze • Report • Defend

---

## ⭐ Project

**BD-OSINT v3**

Bangladesh-focused passive OSINT and defensive attack-surface discovery framework.

Maintained by the project contributors.
