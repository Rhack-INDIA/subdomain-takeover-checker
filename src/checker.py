"""Rudra Pratap Dalei - Red Team Subdomain Takeover Checker.

High-performance, multi-threaded scanner checking authorized subdomain lists
for NXDOMAIN, dangling CNAMEs, and cloud service takeover fingerprints.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import logging
import os
import re
import socket
import sys
import time
from pathlib import Path
from typing import Any, Iterable, Sequence

import requests
import urllib3

# Suppress insecure HTTPS warnings if user specifies --no-verify-ssl
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Ensure project root is in module search path when executed directly
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

try:
    from src.discovery import enumerate_subdomains, save_discovered_subdomains
    from src.dns_resolver import NAME_NOT_FOUND_CODES, resolve_domain
    from src.exporter import Finding, export_findings
    from src.signatures import SIGNATURES, match_signatures, match_signatures_detailed
except ImportError:
    from discovery import enumerate_subdomains, save_discovered_subdomains
    from dns_resolver import NAME_NOT_FOUND_CODES, resolve_domain
    from exporter import Finding, export_findings
    from signatures import SIGNATURES, match_signatures, match_signatures_detailed

LOGGER = logging.getLogger("takeover_checker")
NO_SUCH_BUCKET = re.compile(r"\bNoSuchBucket\b", re.IGNORECASE)
HOSTNAME_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class Color:
    """ANSI color codes with auto-disable support."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

    @classmethod
    def disable(cls) -> None:
        for attr in ("RESET", "BOLD", "RED", "GREEN", "YELLOW", "BLUE", "MAGENTA", "CYAN", "WHITE"):
            setattr(cls, attr, "")


def normalize_hostname(value: str) -> str:
    """Validate and normalize a hostname from the input list."""
    hostname = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
    if not hostname or len(hostname) > 253:
        raise ValueError("hostname is empty or exceeds 253 characters")
    labels = hostname.split(".")
    if len(labels) < 2 or any(not HOSTNAME_LABEL.fullmatch(label) for label in labels):
        raise ValueError("expected a valid fully qualified hostname")
    return hostname


def read_hostnames(path: Path) -> list[str]:
    """Load, validate, and de-duplicate hostnames while preserving input order."""
    hostnames: list[str] = []
    seen: set[str] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise OSError(f"cannot read input file {path}: {error}") from error

    for line_number, raw_line in enumerate(lines, start=1):
        value = raw_line.strip()
        if not value or value.startswith("#"):
            continue
        try:
            hostname = normalize_hostname(value)
        except (UnicodeError, ValueError) as error:
            raise ValueError(f"{path}:{line_number}: {error}") from error
        if hostname not in seen:
            hostnames.append(hostname)
            seen.add(hostname)
    return hostnames


def is_name_not_found(error: socket.gaierror) -> bool:
    """Return whether the resolver reports a missing name, not a general DNS failure."""
    return error.errno in NAME_NOT_FOUND_CODES


def check_hostname(
    hostname: str,
    timeout: float = 5.0,
    verify_ssl: bool = True,
    proxy: str | None = None,
    custom_headers: dict[str, str] | None = None,
    retries: int = 0,
    delay: float = 0.0,
) -> list[Finding]:
    """Scan one hostname for DNS anomalies and provider response signatures."""
    if delay > 0:
        time.sleep(delay)

    dns_info = resolve_domain(hostname, timeout=min(timeout, 3.0))

    # 1. Check for NXDOMAIN status
    if dns_info.is_nxdomain:
        cname = dns_info.canonical_cname
        if cname:
            # Check if CNAME points to a known cloud provider
            matched = match_signatures_detailed("", cname=cname)
            if matched:
                m = matched[0]
                return [
                    Finding(
                        hostname=hostname,
                        service=m.service_name,
                        cname=cname,
                        reason=f"NXDOMAIN with dangling CNAME to {m.service_name} ({cname})",
                        severity=m.severity,
                        confidence=m.confidence,
                        remediation=m.remediation,
                    )
                ]
            return [
                Finding(
                    hostname=hostname,
                    service=None,
                    cname=cname,
                    reason=f"NXDOMAIN with dangling CNAME ({cname})",
                    severity="HIGH",
                    confidence="HIGH",
                    remediation=f"Remove dangling CNAME pointing to {cname} or register the destination resource.",
                )
            ]
        return [
            Finding(
                hostname=hostname,
                service=None,
                cname=None,
                reason="NXDOMAIN candidate",
                severity="MEDIUM",
                confidence="TENTATIVE",
            )
        ]

    # If DNS lookup had a non-NXDOMAIN fatal error
    if dns_info.error:
        LOGGER.error("%s: DNS lookup failed: %s", hostname, dns_info.error)
        return []

    # 2. Check HTTP / HTTPS responses against fingerprint catalog
    cname = dns_info.canonical_cname
    proxies = {"http": proxy, "https": proxy} if proxy else None
    req_headers = {"User-Agent": "SubdomainTakeoverChecker/2.0 (RedTeam-Audit)"}
    if custom_headers:
        req_headers.update(custom_headers)

    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}/"
        response = None
        attempts = 0
        max_attempts = max(1, retries + 1)

        while attempts < max_attempts:
            attempts += 1
            try:
                response = requests.get(
                    url,
                    timeout=timeout,
                    allow_redirects=False,
                    verify=verify_ssl,
                    headers=req_headers,
                    proxies=proxies,
                )
                break
            except requests.RequestException as error:
                if attempts >= max_attempts:
                    LOGGER.warning("%s: %s request failed: %s", hostname, scheme.upper(), error)
                time.sleep(0.1)

        if response is None:
            continue

        # Check for NoSuchBucket explicitly for backwards compatibility
        if NO_SUCH_BUCKET.search(response.text):
            return [
                Finding(
                    hostname=hostname,
                    service="AWS S3",
                    cname=cname,
                    reason=f"NoSuchBucket marker ({response.status_code})",
                    status_code=response.status_code,
                    severity="CRITICAL",
                    confidence="CONFIRMED",
                    remediation="Claim the matching S3 bucket in the configured AWS region, or delete the dangling DNS record.",
                )
            ]

        # Scan against expanded provider fingerprints
        detailed_matches = match_signatures_detailed(response.text, cname=cname)
        if detailed_matches:
            m = detailed_matches[0]
            return [
                Finding(
                    hostname=hostname,
                    service=m.service_name,
                    cname=cname,
                    reason=f"{m.service_name} marker ({response.status_code})",
                    status_code=response.status_code,
                    severity=m.severity,
                    confidence=m.confidence,
                    remediation=m.remediation,
                )
            ]

    # If HTTP requests succeeded but no body matched, check if dangling CNAME exists
    if cname:
        cname_matches = match_signatures_detailed("", cname=cname)
        if cname_matches:
            m = cname_matches[0]
            return [
                Finding(
                    hostname=hostname,
                    service=m.service_name,
                    cname=cname,
                    reason=f"Dangling CNAME pointing to {m.service_name} ({cname})",
                    severity=m.severity,
                    confidence=m.confidence,
                    remediation=m.remediation,
                )
            ]

    return []


def scan_hostnames(
    hostnames: Sequence[str],
    threads: int = 10,
    timeout: float = 5.0,
    verify_ssl: bool = True,
    proxy: str | None = None,
    custom_headers: dict[str, str] | None = None,
    retries: int = 0,
    delay: float = 0.0,
) -> list[Finding]:
    """Scan multiple hostnames concurrently using a thread pool."""
    all_findings: list[Finding] = []
    total = len(hostnames)
    completed = 0

    if threads <= 1 or total <= 1:
        for idx, hostname in enumerate(hostnames, start=1):
            LOGGER.info("[%d/%d] Scanning %s", idx, total, hostname)
            results = check_hostname(
                hostname,
                timeout=timeout,
                verify_ssl=verify_ssl,
                proxy=proxy,
                custom_headers=custom_headers,
                retries=retries,
                delay=delay,
            )
            all_findings.extend(results)
        return all_findings

    workers = min(threads, total)
    LOGGER.info("Scanning %d hostname(s) with %d threads...", total, workers)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_host = {
            executor.submit(
                check_hostname,
                host,
                timeout,
                verify_ssl,
                proxy,
                custom_headers,
                retries,
                delay,
            ): host
            for host in hostnames
        }
        for future in concurrent.futures.as_completed(future_to_host):
            host = future_to_host[future]
            completed += 1
            try:
                results = future.result()
                if results:
                    finding = results[0]
                    sev_label = finding.severity.upper()
                    sev_colored = (
                        f"{Color.RED}{Color.BOLD}[{sev_label}]{Color.RESET}"
                        if sev_label == "CRITICAL"
                        else f"{Color.YELLOW}{Color.BOLD}[{sev_label}]{Color.RESET}"
                    )
                    LOGGER.info(
                        "[%d/%d] [+] VULNERABLE / CANDIDATE: %s -> %s",
                        completed,
                        total,
                        host,
                        finding.reason,
                    )
                    print(
                        f"  {Color.GREEN}[+]{Color.RESET} {sev_colored} {Color.BOLD}{host}{Color.RESET} "
                        f"-> {finding.reason} ({finding.service or 'Unclaimed'})"
                    )
                    all_findings.extend(results)
                else:
                    LOGGER.debug("[%d/%d] [OK] %s", completed, total, host)
            except Exception as exc:
                LOGGER.error("[%d/%d] Error checking %s: %s", completed, total, host, exc)

    return all_findings


def write_results(
    path: Path,
    findings: Iterable[Any],
    export_format: str = "text",
    report_title: str = "Subdomain Takeover Assessment Report",
) -> int:
    """Write findings to disk in the chosen format (text, json, csv, html, legacy)."""
    normalized_findings: list[Finding] = []
    for item in findings:
        if isinstance(item, Finding):
            normalized_findings.append(item)
        elif isinstance(item, (tuple, list)) and len(item) == 2:
            normalized_findings.append(Finding(hostname=item[0], reason=item[1]))

    return export_findings(
        path,
        normalized_findings,
        export_format=export_format,
        report_title=report_title,
    )


def configure_logging(path: Path, verbose: bool = False) -> None:
    """Set up structured logging with file and console output."""
    path.parent.mkdir(parents=True, exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(path, mode="w", encoding="utf-8"),
            logging.StreamHandler(),
        ],
        force=True,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command line flags and options."""
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Rudra Pratap Dalei - Red Team Subdomain Takeover Scanner.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-i", "--input",
        type=Path,
        default=project_root / "evidence" / "sample_data.txt",
        help="Path to file containing one hostname per line",
    )
    parser.add_argument(
        "-d", "--domain",
        type=str,
        default=None,
        help="Target root domain to passively enumerate via Certificate Transparency & OSINT (e.g. example.com)",
    )
    parser.add_argument(
        "--save-subdomains",
        type=Path,
        default=None,
        help="Path to save passively discovered subdomains to a text file",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=project_root / "takeover_targets.txt",
        help="Path to save scan findings",
    )
    parser.add_argument(
        "-l", "--log",
        type=Path,
        default=project_root / "logs" / "output.log",
        help="Path to write execution log",
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="Number of concurrent worker threads",
    )
    parser.add_argument(
        "-w", "--timeout",
        type=float,
        default=5.0,
        help="HTTP/DNS timeout in seconds",
    )
    parser.add_argument(
        "-f", "--format",
        choices=["text", "json", "csv", "html", "legacy"],
        default="text",
        help="Output export format",
    )
    parser.add_argument(
        "-k", "--no-verify-ssl",
        action="store_true",
        help="Disable SSL/TLS certificate verification (useful for dangling HTTPS endpoints)",
    )
    parser.add_argument(
        "-p", "--proxy",
        type=str,
        default=None,
        help="HTTP or SOCKS5 proxy URL (e.g. http://127.0.0.1:8080)",
    )
    parser.add_argument(
        "-H", "--header",
        action="append",
        dest="headers",
        help="Custom HTTP header in 'Name: Value' format (can be specified multiple times)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Delay in seconds between requests for rate limiting",
    )
    parser.add_argument(
        "-r", "--retries",
        type=int,
        default=0,
        help="Number of retries on HTTP request connection error or timeout",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in terminal output",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose DEBUG level logging",
    )
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if args.threads <= 0:
        parser.error("--threads must be at least 1")
    if args.delay < 0:
        parser.error("--delay must be zero or positive")
    if args.retries < 0:
        parser.error("--retries must be zero or positive")
    return args


def parse_custom_headers(raw_headers: list[str] | None) -> dict[str, str]:
    """Parse list of 'Key: Value' header strings into dictionary."""
    headers: dict[str, str] = {}
    if not raw_headers:
        return headers
    for h in raw_headers:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
        else:
            LOGGER.warning("Ignoring malformed header argument: '%s'", h)
    return headers


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for the scanner."""
    args = parse_args(argv)
    if args.no_color or not sys.stdout.isatty():
        Color.disable()

    start_time = time.time()
    try:
        configure_logging(args.log, verbose=args.verbose)

        # Determine target hostnames: from passive domain enumeration or from input file
        hostnames: list[str] = []
        if args.domain:
            LOGGER.info("Passively enumerating subdomains for root domain: %s", args.domain)
            discovered = enumerate_subdomains(args.domain, timeout=args.timeout)
            if args.save_subdomains:
                save_discovered_subdomains(args.save_subdomains, discovered)
                LOGGER.info("Saved %d discovered subdomain(s) to %s", len(discovered), args.save_subdomains)
            hostnames.extend(discovered)

        # If input file was also provided or domain was not specified, load from file
        if not args.domain or (args.input and args.input.exists() and args.input.name != "sample_data.txt"):
            if args.input and args.input.exists():
                file_hosts = read_hostnames(args.input)
                LOGGER.info("Loaded %d target(s) from %s", len(file_hosts), args.input)
                # Deduplicate while preserving order
                for h in file_hosts:
                    if h not in hostnames:
                        hostnames.append(h)

        if not hostnames:
            LOGGER.warning("No hostnames found to scan. Please specify --domain or a valid --input file.")
            return 1

        LOGGER.info("Starting scan on %d target hostname(s)", len(hostnames))
        print(f"\n{Color.CYAN}{Color.BOLD}>>> Subdomain Takeover Scanner Starting{Color.RESET}")
        print(f"    Targets     : {len(hostnames)}")
        print(f"    Concurrency : {args.threads} threads")
        print(f"    Timeout     : {args.timeout}s")
        if args.proxy:
            print(f"    Proxy       : {args.proxy}")
        print(f"{Color.CYAN}------------------------------------------------------------{Color.RESET}\n")

        custom_headers = parse_custom_headers(args.headers)
        findings = scan_hostnames(
            hostnames=hostnames,
            threads=args.threads,
            timeout=args.timeout,
            verify_ssl=not args.no_verify_ssl,
            proxy=args.proxy,
            custom_headers=custom_headers,
            retries=args.retries,
            delay=args.delay,
        )

        # Automatically adjust output format if user specified .html in output path
        chosen_format = args.format
        if chosen_format == "text" and str(args.output).lower().endswith(".html"):
            chosen_format = "html"

        count = write_results(
            args.output,
            findings,
            export_format=chosen_format,
            report_title=f"Subdomain Takeover Report - {args.domain or args.input.stem}",
        )
    except (OSError, ValueError) as error:
        LOGGER.error("Fatal error: %s", error)
        return 2

    elapsed = time.time() - start_time
    LOGGER.info(
        "Completed scan in %.2f seconds. Found %d candidate(s); results written to %s",
        elapsed,
        count,
        args.output,
    )

    critical_count = sum(1 for f in findings if f.severity.upper() == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity.upper() == "HIGH")

    print("\n" + "=" * 55)
    print(f"  {Color.BOLD}SCAN SUMMARY{Color.RESET}")
    print("=" * 55)
    print(f"  Targets Scanned    : {len(hostnames)}")
    print(f"  Candidates Found   : {Color.BOLD}{count}{Color.RESET}")
    if count > 0:
        print(f"  {Color.RED}Critical Severity{Color.RESET}  : {critical_count}")
        print(f"  {Color.YELLOW}High Severity{Color.RESET}      : {high_count}")
    print(f"  Export Format      : {chosen_format.upper()}")
    print(f"  Output File        : {args.output}")
    print(f"  Execution Time     : {elapsed:.2f}s")
    print("=" * 55 + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
