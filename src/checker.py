"""Rudra Pratap Dalei - Red Team Subdomain Takeover Checker.

High-performance, multi-threaded scanner checking authorized subdomain lists
for NXDOMAIN, dangling CNAMEs, and cloud service takeover fingerprints.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import logging
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
    from src.dns_resolver import NAME_NOT_FOUND_CODES, resolve_domain
    from src.exporter import Finding, export_findings
    from src.signatures import SIGNATURES, match_signatures
except ImportError:
    from dns_resolver import NAME_NOT_FOUND_CODES, resolve_domain
    from exporter import Finding, export_findings
    from signatures import SIGNATURES, match_signatures

LOGGER = logging.getLogger("takeover_checker")
NO_SUCH_BUCKET = re.compile(r"\bNoSuchBucket\b", re.IGNORECASE)
HOSTNAME_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


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
) -> list[Finding]:
    """Scan one hostname for DNS anomalies and provider response signatures."""
    dns_info = resolve_domain(hostname, timeout=min(timeout, 3.0))

    # 1. Check for NXDOMAIN status
    if dns_info.is_nxdomain:
        cname = dns_info.canonical_cname
        if cname:
            # Check if CNAME points to a known cloud provider
            matched = match_signatures("", cname=cname)
            if matched:
                service, _ = matched[0]
                return [
                    Finding(
                        hostname=hostname,
                        service=service,
                        cname=cname,
                        reason=f"NXDOMAIN with dangling CNAME to {service} ({cname})",
                    )
                ]
            return [
                Finding(
                    hostname=hostname,
                    service=None,
                    cname=cname,
                    reason=f"NXDOMAIN with dangling CNAME ({cname})",
                )
            ]
        return [Finding(hostname=hostname, service=None, cname=None, reason="NXDOMAIN candidate")]

    # If DNS lookup had a non-NXDOMAIN fatal error
    if dns_info.error:
        LOGGER.error("%s: DNS lookup failed: %s", hostname, dns_info.error)
        return []

    # 2. Check HTTP / HTTPS responses against fingerprint catalog
    cname = dns_info.canonical_cname
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}/"
        try:
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=False,
                verify=verify_ssl,
                headers={"User-Agent": "SubdomainTakeoverChecker/2.0"},
            )
        except requests.RequestException as error:
            LOGGER.warning("%s: %s request failed: %s", hostname, scheme.upper(), error)
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
                )
            ]

        # Scan against expanded provider fingerprints
        matches = match_signatures(response.text, cname=cname)
        if matches:
            service, reason_desc = matches[0]
            return [
                Finding(
                    hostname=hostname,
                    service=service,
                    cname=cname,
                    reason=f"{service} marker ({response.status_code})",
                    status_code=response.status_code,
                )
            ]

    # If HTTP requests succeeded but no body matched, check if dangling CNAME exists
    if cname:
        cname_matches = match_signatures("", cname=cname)
        if cname_matches:
            service, reason = cname_matches[0]
            return [
                Finding(
                    hostname=hostname,
                    service=service,
                    cname=cname,
                    reason=f"Dangling CNAME pointing to {service} ({cname})",
                )
            ]

    return []


def scan_hostnames(
    hostnames: Sequence[str],
    threads: int = 10,
    timeout: float = 5.0,
    verify_ssl: bool = True,
) -> list[Finding]:
    """Scan multiple hostnames concurrently using a thread pool."""
    all_findings: list[Finding] = []
    total = len(hostnames)
    completed = 0

    if threads <= 1 or total <= 1:
        for idx, hostname in enumerate(hostnames, start=1):
            LOGGER.info("[%d/%d] Scanning %s", idx, total, hostname)
            results = check_hostname(hostname, timeout=timeout, verify_ssl=verify_ssl)
            all_findings.extend(results)
        return all_findings

    workers = min(threads, total)
    LOGGER.info("Scanning %d hostname(s) with %d threads...", total, workers)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_host = {
            executor.submit(check_hostname, host, timeout, verify_ssl): host
            for host in hostnames
        }
        for future in concurrent.futures.as_completed(future_to_host):
            host = future_to_host[future]
            completed += 1
            try:
                results = future.result()
                if results:
                    LOGGER.info(
                        "[%d/%d] [+] VULNERABLE / CANDIDATE: %s -> %s",
                        completed,
                        total,
                        host,
                        results[0].reason,
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
) -> int:
    """Write findings to disk in the chosen format (text, json, csv, legacy)."""
    normalized_findings: list[Finding] = []
    for item in findings:
        if isinstance(item, Finding):
            normalized_findings.append(item)
        elif isinstance(item, (tuple, list)) and len(item) == 2:
            normalized_findings.append(Finding(hostname=item[0], reason=item[1]))

    return export_findings(path, normalized_findings, export_format=export_format)


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
        "-o", "--output",
        type=Path,
        default=project_root / "takeover_targets.txt",
        help="Path to save candidate results",
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
        choices=["text", "json", "csv", "legacy"],
        default="text",
        help="Output export format",
    )
    parser.add_argument(
        "-k", "--no-verify-ssl",
        action="store_true",
        help="Disable SSL/TLS certificate verification (useful for dangling HTTPS endpoints)",
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
    return args


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for the scanner."""
    args = parse_args(argv)
    start_time = time.time()
    try:
        configure_logging(args.log, verbose=args.verbose)
        hostnames = read_hostnames(args.input)
        LOGGER.info("Starting scan on %d target hostname(s)", len(hostnames))

        findings = scan_hostnames(
            hostnames=hostnames,
            threads=args.threads,
            timeout=args.timeout,
            verify_ssl=not args.no_verify_ssl,
        )

        count = write_results(args.output, findings, export_format=args.format)
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
    print("\n" + "=" * 50)
    print(f"  SCAN SUMMARY")
    print("=" * 50)
    print(f"  Targets Scanned : {len(hostnames)}")
    print(f"  Candidates Found: {count}")
    print(f"  Format          : {args.format.upper()}")
    print(f"  Output File     : {args.output}")
    print(f"  Execution Time  : {elapsed:.2f}s")
    print("=" * 50 + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
