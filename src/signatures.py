"""Signatures and fingerprinted response patterns for common takeover-susceptible cloud services."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Pattern


@dataclass(frozen=True)
class ServiceSignature:
    """Represents a fingerprint for a cloud provider susceptible to subdomain takeover."""

    service_name: str
    body_patterns: list[Pattern[str]]
    cname_patterns: list[str] = field(default_factory=list)
    discussion_url: str = ""

    def matches_body(self, text: str) -> Pattern[str] | None:
        """Return the first matching regex pattern if found in response text, else None."""
        for pattern in self.body_patterns:
            if pattern.search(text):
                return pattern
        return None

    def matches_cname(self, cname: str) -> str | None:
        """Return matching CNAME keyword if found in canonical name, else None."""
        cname_lower = cname.lower()
        for kw in self.cname_patterns:
            if kw.lower() in cname_lower:
                return kw
        return None


# Catalog of recognized provider signatures
SIGNATURES: list[ServiceSignature] = [
    ServiceSignature(
        service_name="AWS S3",
        cname_patterns=["s3.amazonaws.com", "s3-website", "s3.dualstack."],
        body_patterns=[
            re.compile(r"\bNoSuchBucket\b", re.IGNORECASE),
            re.compile(r"The specified bucket does not exist", re.IGNORECASE),
        ],
        discussion_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteHosting.html",
    ),
    ServiceSignature(
        service_name="AWS CloudFront",
        cname_patterns=["cloudfront.net"],
        body_patterns=[
            re.compile(r"ERROR:\s*The request could not be satisfied", re.IGNORECASE),
            re.compile(r"Bad Request:\s*ERROR: The request could not be satisfied", re.IGNORECASE),
        ],
    ),
    ServiceSignature(
        service_name="GitHub Pages",
        cname_patterns=["github.io"],
        body_patterns=[
            re.compile(r"There isn't a GitHub Pages site here", re.IGNORECASE),
            re.compile(r"For root URLs \(like http://example\.com/\) you must provide an index\.html file", re.IGNORECASE),
        ],
    ),
    ServiceSignature(
        service_name="Heroku",
        cname_patterns=["herokuapp.com", "herokussl.com", "herokudns.com"],
        body_patterns=[
            re.compile(r"No such app", re.IGNORECASE),
            re.compile(r"There's nothing here, yet\.", re.IGNORECASE),
            re.compile(r"<title>No such app</title>", re.IGNORECASE),
        ],
    ),
    ServiceSignature(
        service_name="Microsoft Azure",
        cname_patterns=["azurewebsites.net", "cloudapp.net", "azureedge.net", "blob.core.windows.net"],
        body_patterns=[
            re.compile(r"404 Web Site not found", re.IGNORECASE),
            re.compile(r"The specified account does not exist", re.IGNORECASE),
            re.compile(r"The resource you are looking for has been removed", re.IGNORECASE),
        ],
    ),
    ServiceSignature(
        service_name="Shopify",
        cname_patterns=["myshopify.com"],
        body_patterns=[
            re.compile(r"Sorry, this shop is currently unavailable", re.IGNORECASE),
            re.compile(r"Only one step left to start selling", re.IGNORECASE),
        ],
    ),
    ServiceSignature(
        service_name="Fastly",
        cname_patterns=["fastly.net"],
        body_patterns=[
            re.compile(r"Fastly error:\s*unknown domain", re.IGNORECASE),
        ],
    ),
    ServiceSignature(
        service_name="Surge.sh",
        cname_patterns=["surge.sh"],
        body_patterns=[
            re.compile(r"project not found", re.IGNORECASE),
        ],
    ),
    ServiceSignature(
        service_name="Ghost",
        cname_patterns=["ghost.io"],
        body_patterns=[
            re.compile(r"The thing you were looking for is no longer here", re.IGNORECASE),
        ],
    ),
    ServiceSignature(
        service_name="ReadTheDocs",
        cname_patterns=["readthedocs.io"],
        body_patterns=[
            re.compile(r"is not hosted by Read the Docs", re.IGNORECASE),
            re.compile(r"unknown to Read the Docs", re.IGNORECASE),
        ],
    ),
    ServiceSignature(
        service_name="Bitbucket",
        cname_patterns=["bitbucket.io"],
        body_patterns=[
            re.compile(r"Repository not found", re.IGNORECASE),
        ],
    ),
    ServiceSignature(
        service_name="Zendesk",
        cname_patterns=["zendesk.com"],
        body_patterns=[
            re.compile(r"Help Center Closed", re.IGNORECASE),
        ],
    ),
    ServiceSignature(
        service_name="Pantheon",
        cname_patterns=["pantheonsite.io"],
        body_patterns=[
            re.compile(r"The gods are wise, but do not know of the site which you seek", re.IGNORECASE),
        ],
    ),
    ServiceSignature(
        service_name="Tumblr",
        cname_patterns=["domains.tumblr.com"],
        body_patterns=[
            re.compile(r"Whatever you were looking for doesn't seem to exist at this URL", re.IGNORECASE),
        ],
    ),
    ServiceSignature(
        service_name="WordPress.com",
        cname_patterns=["wordpress.com"],
        body_patterns=[
            re.compile(r"Do you want to register", re.IGNORECASE),
            re.compile(r"doesn&#8217;t exist", re.IGNORECASE),
        ],
    ),
    ServiceSignature(
        service_name="Unbounce",
        cname_patterns=["unbouncepages.com"],
        body_patterns=[
            re.compile(r"The requested URL was not found on this server", re.IGNORECASE),
        ],
    ),
    ServiceSignature(
        service_name="Helpjuice",
        cname_patterns=["helpjuice.com"],
        body_patterns=[
            re.compile(r"We could not find what you're looking for", re.IGNORECASE),
        ],
    ),
    ServiceSignature(
        service_name="Cargo Collective",
        cname_patterns=["cargocollective.com", "cargo.site"],
        body_patterns=[
            re.compile(r"404 Not Found", re.IGNORECASE),
        ],
    ),
]


def match_signatures(body: str, cname: str | None = None) -> list[tuple[str, str]]:
    """Scan response body and CNAME against known signatures.

    Returns a list of (service_name, reason_description).
    """
    matches: list[tuple[str, str]] = []

    # Check body patterns
    for sig in SIGNATURES:
        pattern = sig.matches_body(body)
        if pattern:
            matches.append((sig.service_name, f"{sig.service_name} marker detected ({pattern.pattern})"))

    # If no body match but CNAME explicitly points to a provider known for dangling CNAME takeover
    if not matches and cname:
        for sig in SIGNATURES:
            cname_match = sig.matches_cname(cname)
            if cname_match:
                matches.append((sig.service_name, f"Points via CNAME to {cname} ({sig.service_name})"))

    return matches
