# BD-OSINT v3

**Bangladesh-focused passive OSINT and defensive attack-surface discovery framework.**

BD-OSINT collects publicly available information about a domain — DNS, RDAP
registration data, Certificate Transparency logs, historical archive URLs,
security.txt, TLS certificate metadata, and public HTTP response metadata —
and produces structured JSON/CSV/HTML reports with conservative,
evidence-based findings.

## Ethics & Legal

- Passive modules touch only public data providers and the target's own public
  web endpoint — one harmless GET each.
- **Active scanning (ports, AXFR) is disabled by default** and requires
  `--profile authorized`. You must hold documented permission for the target.
- The tool never performs credential theft, phishing, brute force,
  exploitation, authentication bypass, WAF/CAPTCHA evasion, or lookups of
  private citizen data (NID, phone location, call records).
- Missing security headers or "interesting" subdomain names are reported as
  **informational observations** — never automatically as vulnerabilities.
- Findings are labeled `observed`, `potential`, or `verified`.
- Sensitive Bangladesh categories (`.gov.bd`, `.edu.bd`, `.ac.bd`)
  automatically get conservative rate limits.

## Features

- Modules: `dns, rdap, crtsh, wayback, tls, headers, tech, securitytxt, http, subdomains`
- Authorized-only: `ports` (nmap wrapper), `axfr` (DNS zone transfer test)
- Bangladesh TLD intelligence (Government / Education / Academic / …)
- Scope enforcement — the tool never expands beyond the supplied scope
- TTL filesystem cache, per-provider rate limiting
- Automatic redaction of token/password/secret patterns in all reports
- Reports: JSON, CSV, responsive HTML dashboard, relationship graph
- Structured findings engine (severity / confidence / status / recommendation)

## Installation

```bash
git clone <repo-url> bd-osint && cd bd-osint
bash setup.sh            # or: python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
# optional:
sudo apt install graphviz nmap
