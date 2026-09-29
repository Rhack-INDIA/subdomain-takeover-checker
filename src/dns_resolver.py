"""DNS resolution utilities with CNAME chain analysis and NXDOMAIN identification."""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass, field
from typing import Sequence

try:
    import dns.exception
    import dns.name
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

LOGGER = logging.getLogger("takeover_checker.dns")

NAME_NOT_FOUND_CODES = {
    code
    for code in (
        getattr(socket, "EAI_NONAME", None),
        getattr(socket, "EAI_NODATA", None),
    )
    if code is not None
}


@dataclass
class DnsLookupResult:
    """Detailed DNS lookup result for a hostname."""

    hostname: str
    is_nxdomain: bool = False
    cnames: list[str] = field(default_factory=list)
    canonical_cname: str | None = None
    ip_addresses: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def has_cname(self) -> bool:
        return bool(self.canonical_cname)

    @property
    def is_resolvable(self) -> bool:
        return bool(self.ip_addresses)


def _resolve_with_dnspython(hostname: str, timeout: float = 3.0) -> DnsLookupResult:
    """Resolve hostname and trace CNAME chain using dnspython."""
    result = DnsLookupResult(hostname=hostname)
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    # 1. Trace CNAME records
    try:
        cname_answer = resolver.resolve(hostname, "CNAME")
        for rdata in cname_answer:
            target = str(rdata.target).rstrip(".")
            result.cnames.append(target)
            result.canonical_cname = target
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass
    except dns.resolver.NXDOMAIN:
        result.is_nxdomain = True
        return result
    except dns.exception.DNSException as e:
        LOGGER.debug("%s: CNAME lookup note: %s", hostname, e)

    # 2. Check A / AAAA addresses
    try:
        a_answer = resolver.resolve(hostname, "A")
        for rdata in a_answer:
            result.ip_addresses.append(rdata.address)
    except dns.resolver.NXDOMAIN:
        result.is_nxdomain = True
        return result
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass
    except dns.exception.Timeout:
        result.error = "DNS lookup timeout"
        return result
    except dns.exception.DNSException as e:
        result.error = str(e)
        return result

    # Also resolve AAAA if no A records found
    if not result.ip_addresses:
        try:
            aaaa_answer = resolver.resolve(hostname, "AAAA")
            for rdata in aaaa_answer:
                result.ip_addresses.append(rdata.address)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            pass

    return result


def _resolve_with_socket(hostname: str) -> DnsLookupResult:
    """Fallback resolution using standard library socket."""
    result = DnsLookupResult(hostname=hostname)
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, _, _, canonname, sockaddr in infos:
            ip = sockaddr[0]
            if ip not in result.ip_addresses:
                result.ip_addresses.append(ip)
            if canonname and canonname.lower() != hostname.lower():
                result.canonical_cname = canonname.rstrip(".")
    except socket.gaierror as error:
        if error.errno in NAME_NOT_FOUND_CODES:
            result.is_nxdomain = True
        else:
            result.error = f"DNS lookup failed: {error}"
    except OSError as error:
        result.error = f"DNS lookup failed: {error}"

    return result


def resolve_domain(hostname: str, timeout: float = 3.0) -> DnsLookupResult:
    """Resolve domain using dnspython when available, with socket fallback."""
    if HAS_DNSPYTHON:
        try:
            return _resolve_with_dnspython(hostname, timeout=timeout)
        except Exception as e:
            LOGGER.debug("dnspython error on %s, falling back to socket: %s", hostname, e)
    return _resolve_with_socket(hostname)
