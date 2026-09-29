# Rudra Pratap Dalei - Red Team Subdomain Takeover Scanner

[![CI](https://github.com/Rhack-INDIA/subdomain-takeover-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/Rhack-INDIA/subdomain-takeover-checker/actions/workflows/ci.yml)
![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A high-performance, concurrent Python red-teaming tool designed to scan authorized lists of subdomains for takeover-related signals, including:

- **NXDOMAIN Candidates & Dangling CNAMEs:** Identifies unresolved subdomains and canonical name (CNAME) chains pointing to unclaimed third-party resources.
- **Multi-Cloud Fingerprint Signatures:** Inspects HTTP/HTTPS responses across leading cloud hosting, SaaS, and CDN providers for unclaimed resource error markers.
- **Concurrent Multi-Threading:** Rapid scanning of large target inventories utilizing dynamic worker pools.
- **Flexible Multi-Format Reporting:** Export findings to aligned plain text, RFC 4180 CSV, or structured JSON.
- **Automated CI/CD:** Integrated GitHub Actions workflow running cross-platform tests across Python 3.10 through 3.13.

> [!NOTE]
> These signals are leads, not proof of a takeover. A missing DNS record or matching provider error page must be verified against current DNS configuration and cloud tenant claims before reporting.

---

## Supported Provider Signatures

The scanner recognizes fingerprinted response patterns and dangling CNAME targets for:

| Provider | CNAME Indicators | Signature Examples |
| :--- | :--- | :--- |
| **AWS S3 / CloudFront** | `*.s3.amazonaws.com`, `*.cloudfront.net` | `NoSuchBucket`, `The request could not be satisfied` |
| **GitHub Pages** | `*.github.io` | `There isn't a GitHub Pages site here` |
| **Heroku** | `*.herokuapp.com`, `*.herokussl.com` | `No such app`, `There's nothing here, yet.` |
| **Microsoft Azure** | `*.azurewebsites.net`, `*.cloudapp.net` | `404 Web Site not found`, `The specified account does not exist` |
| **Shopify** | `*.myshopify.com` | `Sorry, this shop is currently unavailable` |
| **Fastly CDN** | `*.fastly.net` | `Fastly error: unknown domain` |
| **Surge.sh** | `*.surge.sh` | `project not found` |
| **Ghost** | `*.ghost.io` | `The thing you were looking for is no longer here` |
| **ReadTheDocs** | `*.readthedocs.io` | `is not hosted by Read the Docs` |
| **Zendesk** | `*.zendesk.com` | `Help Center Closed` |
| **Bitbucket** | `*.bitbucket.io` | `Repository not found` |
| **Pantheon** | `*.pantheonsite.io` | `The gods are wise, but do not know of the site which you seek` |
| **Tumblr** | `domains.tumblr.com` | `Whatever you were looking for doesn't seem to exist at this URL` |
| **WordPress.com** | `*.wordpress.com` | `Do you want to register`, `doesn't exist` |
| **Unbounce** | `*.unbouncepages.com` | `The requested URL was not found on this server` |

---

## Requirements & Setup

* Python 3.10+
* Dependencies: `requests`, `dnspython`

Clone the repository and install dependencies in a virtual environment:

```powershell
# Clone repo
git clone https://github.com/Rhack-INDIA/subdomain-takeover-checker.git
cd subdomain-takeover-checker

# Set up virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt
```

---

## Usage

### Quick Scan
Place target hostnames in a text file (one per line; empty lines and lines starting with `#` are ignored), then execute:

```powershell
python src\checker.py --input evidence\sample_data.txt
```

### Advanced Scan Options
```powershell
python src\checker.py -i targets.txt -o findings.json -f json -t 20 -w 4.0 -k
```

### Command-Line Arguments

| Flag | Long Flag | Default | Description |
| :--- | :--- | :--- | :--- |
| `-i` | `--input` | `evidence/sample_data.txt` | Path to target hostname list file. |
| `-o` | `--output` | `takeover_targets.txt` | Path to save scan findings. |
| `-l` | `--log` | `logs/output.log` | Path for run logs. |
| `-t` | `--threads` | `10` | Number of concurrent worker threads. |
| `-w` | `--timeout` | `5.0` | HTTP and DNS timeout in seconds. |
| `-f` | `--format` | `text` | Export format: `text`, `json`, `csv`, or `legacy`. |
| `-k` | `--no-verify-ssl` | `False` | Ignore SSL/TLS validation (for dangling custom certs). |
| `-v` | `--verbose` | `False` | Enable detailed debug logging. |

---

## Output Formats

### JSON (`-f json`)
```json
[
  {
    "hostname": "docs.example.com",
    "service": "GitHub Pages",
    "cname": "org.github.io",
    "reason": "GitHub Pages marker (404)",
    "status_code": 404,
    "timestamp": "2026-09-29T12:00:00Z"
  }
]
```

### CSV (`-f csv`)
```csv
hostname,service,cname,reason,status_code,timestamp
docs.example.com,GitHub Pages,org.github.io,GitHub Pages marker (404),404,2026-09-29T12:00:00Z
```

### Aligned Text (`-f text`)
```text
docs.example.com	GitHub Pages	org.github.io	GitHub Pages marker (404)
missing.example.com	N/A	None	NXDOMAIN candidate
```

---

## Project Structure

```text
.
|-- .github/
|   `-- workflows/
|       `-- ci.yml              # Automated cross-platform CI workflow
|-- evidence/
|   `-- sample_data.txt         # Sample subdomain list
|-- logs/
|   `-- output.log              # Run log
|-- screenshots/                # Evidence & run screenshots
|-- src/
|   |-- __init__.py
|   |-- checker.py              # CLI & multi-threaded orchestration
|   |-- dns_resolver.py         # DNS resolution & CNAME analysis
|   |-- exporter.py             # Multi-format report exporters (JSON/CSV/Text)
|   `-- signatures.py           # Multi-cloud takeover fingerprint catalog
|-- tests/
|   `-- test_checker.py         # Comprehensive unit test suite
|-- .gitignore
|-- README.md
|-- requirements.txt
`-- takeover_targets.txt
```

---

## Testing

Run the full offline test suite:

```powershell
python -m unittest discover -s tests -v
```

All network calls and DNS queries are cleanly mocked in unit tests to ensure fast, deterministic CI execution.

---

## Responsible Red-Teaming & Ethics

This tool is created for authorized penetration testing, vulnerability assessments, bug bounty hunting on domains within scope, and defensive security auditing. Only scan targets you have explicit permission to assess. Do not attempt unauthorized takeover of resources.
