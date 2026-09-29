"""Check authorized subdomain lists for basic takeover-related indicators."""

from __future__ import annotations

import argparse
import logging
import re
import socket
import sys
from pathlib import Path
from typing import Iterable

import requests


LOGGER = logging.getLogger("takeover_checker")
NO_SUCH_BUCKET = re.compile(r"\bNoSuchBucket\b", re.IGNORECASE)
HOSTNAME_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
NAME_NOT_FOUND_CODES = {
    code
    for code in (
        getattr(socket, "EAI_NONAME", None),
        getattr(socket, "EAI_NODATA", None),
    )
    if code is not None
}


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


def check_hostname(hostname: str, timeout: float) -> list[tuple[str, str]]:
    """Return indicator/reason pairs for one hostname."""
    try:
        socket.getaddrinfo(hostname, None)
    except socket.gaierror as error:
        if is_name_not_found(error):
            return [(hostname, "NXDOMAIN candidate")]
        LOGGER.error("%s: DNS lookup failed: %s", hostname, error)
        return []
    except OSError as error:
        LOGGER.error("%s: DNS lookup failed: %s", hostname, error)
        return []

    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}/"
        try:
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=False,
                headers={"User-Agent": "SubdomainTakeoverChecker/1.0"},
            )
        except requests.RequestException as error:
            LOGGER.warning("%s: %s request failed: %s", hostname, scheme.upper(), error)
            continue

        if NO_SUCH_BUCKET.search(response.text):
            return [(hostname, f"NoSuchBucket marker ({response.status_code})")]
    return []


def write_results(path: Path, findings: Iterable[tuple[str, str]]) -> int:
    """Write findings as hostname/reason lines and return the number written."""
    results = list(findings)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "".join(f"{hostname}\t{reason}\n" for hostname, reason in results),
            encoding="utf-8",
        )
    except OSError as error:
        raise OSError(f"cannot write output file {path}: {error}") from error
    return len(results)


def configure_logging(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.FileHandler(path, mode="w", encoding="utf-8"),
            logging.StreamHandler(),
        ],
        force=True,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Check authorized subdomains for NXDOMAIN and NoSuchBucket indicators."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=project_root / "evidence" / "sample_data.txt",
        help="file containing one hostname per line",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=project_root / "takeover_targets.txt",
        help="file to write candidate hostnames to",
    )
    parser.add_argument(
        "--log",
        type=Path,
        default=project_root / "logs" / "output.log",
        help="run log path",
    )
    parser.add_argument("--timeout", type=float, default=5.0, help="HTTP timeout in seconds")
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        configure_logging(args.log)
        hostnames = read_hostnames(args.input)
        LOGGER.info("Checking %d hostname(s) from %s", len(hostnames), args.input)
        findings: list[tuple[str, str]] = []
        for hostname in hostnames:
            LOGGER.info("Checking %s", hostname)
            findings.extend(check_hostname(hostname, args.timeout))
        count = write_results(args.output, findings)
    except (OSError, ValueError) as error:
        LOGGER.error("%s", error)
        return 2

    LOGGER.info("Found %d candidate(s); results written to %s", count, args.output)
    print(f"Candidates: {count} (review {args.output})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
