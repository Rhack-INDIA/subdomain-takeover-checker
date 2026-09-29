# Rudra Pratap Dalei - Red Team Subdomain Takeover Checker

A small Python command-line tool for checking an authorized list of subdomains for two takeover-related signals:

- DNS names that fail to resolve with a name-not-found response (reported as an **NXDOMAIN candidate**).
- HTTP response pages containing the `NoSuchBucket` marker.

These signals are leads, not proof of a takeover. A missing DNS name is not necessarily claimable, and a matching page should be verified with the relevant provider and DNS configuration before reporting.

## Requirements

- Python 3.10+
- `requests`

Install the dependency:

```powershell
python -m pip install -r requirements.txt
```

## Usage

Put one hostname per line in a text file (blank lines and lines beginning with `#` are ignored), then run:

```powershell
python src\checker.py --input evidence\sample_data.txt
```

By default, the checker writes candidates to `takeover_targets.txt` and a run log to `logs\output.log`. Override paths and request timeout as needed:

```powershell
python src\checker.py --input targets.txt --output results.txt --log logs\run.log --timeout 8
```

The tool resolves each hostname first. It labels only resolver name-not-found errors as NXDOMAIN candidates; DNS timeouts and other resolver failures are logged as errors rather than treated as vulnerabilities. Resolvable hosts are checked over HTTPS and HTTP, with certificate verification enabled, for the `NoSuchBucket` response marker. Requests are read-only `GET`s.

## Output

The output file contains one candidate hostname per line, with a reason after a tab:

```text
missing.example.invalid	NXDOMAIN candidate
```

No output file entries means no configured indicator was found during that run; it does not establish that a host is safe.

## Project layout

```text
.
|-- README.md
|-- requirements.txt
|-- src/
|   `-- checker.py
|-- screenshots/
|-- logs/
|   `-- output.log
|-- evidence/
|   `-- sample_data.txt
|-- tests/
|   `-- test_checker.py
`-- takeover_targets.txt
```

## Testing

Run the offline unit tests (no DNS or external HTTP calls):

```powershell
python -m unittest discover -s tests -v
```

## Responsible use

Only check systems you own or are explicitly authorized to assess. The checker does not claim cloud resources, modify DNS, or exploit a finding. Confirm suspected dangling records with the domain owner/provider and preserve authorization and evidence before taking further action.

## Screenshots

Add genuine captures of your own run to `screenshots/` before submission, using the requested names `01_setup.png`, `02_output.png`, and `03_findings.png`. Capture the setup/command, the resulting output file, and any verified finding respectively. Do not present sample or simulated output as a real finding.
