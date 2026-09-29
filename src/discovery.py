"""Passive subdomain discovery module using public Certificate Transparency logs and OSINT sources."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Sequence
from urllib.parse import quote

import requests

LOGGER = logging.getLogger("takeover_checker.discovery")
DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


def clean_domain(domain: str) -> str:
    """Normalize and clean a target root domain."""
    cleaned = domain.strip().lower()
    # Strip URL schemes if user passed http:// or https://
    if "://" in cleaned:
        cleaned = cleaned.split("://", 1)[1]
    # Strip paths, ports, or queries
    cleaned = cleaned.split("/", 1)[0].split(":", 1)[0].rstrip(".")
    if not DOMAIN_REGEX.fullmatch(cleaned):
        raise ValueError(f"Invalid domain format: {domain}")
    return cleaned


def query_crt_sh(domain: str, timeout: float = 10.0) -> set[str]:
    """Query Certificate Transparency logs via crt.sh for historical and active subdomains."""
    subdomains: set[str] = set()
    url = f"https://crt.sh/?q=%.{quote(domain)}&output=json"
    headers = {"User-Agent": "SubdomainTakeoverChecker/2.0 (RedTeam-Research)"}

    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        if response.status_code != 200:
            LOGGER.warning("crt.sh returned HTTP status %d for domain %s", response.status_code, domain)
            return subdomains

        data = response.json()
        domain_suffix = f".{domain}"
        for entry in data:
            name_value = entry.get("name_value", "")
            # Certificates can include multiple SANs separated by newlines
            for raw_name in name_value.splitlines():
                candidate = raw_name.strip().lower().lstrip("*.")
                if candidate == domain or candidate.endswith(domain_suffix):
                    # Basic label validity check
                    if DOMAIN_REGEX.fullmatch(candidate):
                        subdomains.add(candidate)
    except requests.RequestException as error:
        LOGGER.warning("Failed querying crt.sh for %s: %s", domain, error)
    except (ValueError, json.JSONDecodeError) as error:
        LOGGER.debug("crt.sh JSON parsing error for %s: %s", domain, error)

    return subdomains


def query_hackertarget(domain: str, timeout: float = 10.0) -> set[str]:
    """Query HackerTarget hostsearch endpoint for passive subdomain enumeration."""
    subdomains: set[str] = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={quote(domain)}"
    headers = {"User-Agent": "SubdomainTakeoverChecker/2.0 (RedTeam-Research)"}

    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        if response.status_code != 200 or "API count exceeded" in response.text:
            return subdomains

        domain_suffix = f".{domain}"
        for line in response.text.splitlines():
            line = line.strip()
            if not line or "," not in line:
                continue
            hostname = line.split(",", 1)[0].strip().lower()
            if hostname == domain or hostname.endswith(domain_suffix):
                if DOMAIN_REGEX.fullmatch(hostname):
                    subdomains.add(hostname)
    except requests.RequestException as error:
        LOGGER.debug("Failed querying HackerTarget for %s: %s", domain, error)

    return subdomains


def enumerate_subdomains(
    domain: str,
    timeout: float = 10.0,
    sources: Sequence[str] | None = None,
) -> list[str]:
    """Passively discover subdomains for a domain using available open source providers."""
    cleaned_root = clean_domain(domain)
    LOGGER.info("Starting passive subdomain enumeration for '%s'...", cleaned_root)

    available_sources = {
        "crt.sh": query_crt_sh,
        "hackertarget": query_hackertarget,
    }

    active_sources = sources or ["crt.sh", "hackertarget"]
    discovered: set[str] = set()

    for source_name in active_sources:
        query_func = available_sources.get(source_name.lower())
        if not query_func:
            LOGGER.warning("Unknown subdomain discovery source: %s", source_name)
            continue
        LOGGER.info("Querying %s for %s...", source_name, cleaned_root)
        try:
            found = query_func(cleaned_root, timeout=timeout)
            LOGGER.info("[%s] Discovered %d subdomain(s)", source_name, len(found))
            discovered.update(found)
        except Exception as err:
            LOGGER.warning("Error running discovery on %s: %s", source_name, err)

    # Always ensure root domain itself is not lost if desired
    sorted_subdomains = sorted(discovered)
    LOGGER.info("Enumeration complete for '%s': %d unique subdomain(s) found", cleaned_root, len(sorted_subdomains))
    return sorted_subdomains


def save_discovered_subdomains(path: Path, subdomains: Sequence[str]) -> int:
    """Save discovered subdomains to a text file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(subdomains) + ("\n" if subdomains else "")
    path.write_text(content, encoding="utf-8")
    return len(subdomains)
