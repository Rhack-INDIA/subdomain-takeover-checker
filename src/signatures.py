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
    severity: str = "HIGH"
    confidence: str = "HIGH"
    remediation: str = ""
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


@dataclass
class SignatureMatch:
    """Detailed result of matching a response or CNAME against a service signature."""

    service_name: str
    reason: str
    signature: ServiceSignature
    severity: str
    confidence: str
    remediation: str


# Catalog of recognized provider signatures
SIGNATURES: list[ServiceSignature] = [
    ServiceSignature(
        service_name="AWS S3",
        cname_patterns=["s3.amazonaws.com", "s3-website", "s3.dualstack."],
        body_patterns=[
            re.compile(r"\bNoSuchBucket\b", re.IGNORECASE),
            re.compile(r"The specified bucket does not exist", re.IGNORECASE),
        ],
        severity="CRITICAL",
        confidence="CONFIRMED",
        remediation="Claim the matching S3 bucket in the configured AWS region, or delete the dangling DNS CNAME/ALIAS record.",
        discussion_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteHosting.html",
    ),
    ServiceSignature(
        service_name="AWS CloudFront",
        cname_patterns=["cloudfront.net"],
        body_patterns=[
            re.compile(r"ERROR:\s*The request could not be satisfied", re.IGNORECASE),
            re.compile(r"Bad Request:\s*ERROR: The request could not be satisfied", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Remove the DNS record pointing to the disabled CloudFront distribution or attach the domain to an active distribution with SSL.",
    ),
    ServiceSignature(
        service_name="GitHub Pages",
        cname_patterns=["github.io"],
        body_patterns=[
            re.compile(r"There isn't a GitHub Pages site here", re.IGNORECASE),
            re.compile(r"For root URLs \(like http://example\.com/\) you must provide an index\.html file", re.IGNORECASE),
        ],
        severity="CRITICAL",
        confidence="CONFIRMED",
        remediation="Create a GitHub repository with GitHub Pages enabled and add the custom domain CNAME, or remove the DNS CNAME record.",
    ),
    ServiceSignature(
        service_name="Heroku",
        cname_patterns=["herokuapp.com", "herokussl.com", "herokudns.com"],
        body_patterns=[
            re.compile(r"No such app", re.IGNORECASE),
            re.compile(r"There's nothing here, yet\.", re.IGNORECASE),
            re.compile(r"<title>No such app</title>", re.IGNORECASE),
        ],
        severity="CRITICAL",
        confidence="CONFIRMED",
        remediation="Register a Heroku application and add the custom domain via Heroku CLI/Dashboard, or delete the dangling CNAME.",
    ),
    ServiceSignature(
        service_name="Microsoft Azure",
        cname_patterns=["azurewebsites.net", "cloudapp.net", "azureedge.net", "blob.core.windows.net", "trafficmanager.net"],
        body_patterns=[
            re.compile(r"404 Web Site not found", re.IGNORECASE),
            re.compile(r"The specified account does not exist", re.IGNORECASE),
            re.compile(r"The resource you are looking for has been removed", re.IGNORECASE),
        ],
        severity="CRITICAL",
        confidence="CONFIRMED",
        remediation="Register the unclaimed Azure App Service or Storage Account name, or remove the dangling DNS record.",
    ),
    ServiceSignature(
        service_name="Cloudflare",
        cname_patterns=["cloudflare.net"],
        body_patterns=[
            re.compile(r"error 1016 origin dns error", re.IGNORECASE),
            re.compile(r"Error 1016", re.IGNORECASE),
            re.compile(r"Origin DNS error", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Fix the origin DNS record in Cloudflare Dashboard or reassign the Cloudflare Custom Hostname.",
    ),
    ServiceSignature(
        service_name="Netlify",
        cname_patterns=["netlify.app", "netlify.com"],
        body_patterns=[
            re.compile(r"Not Found - Request ID", re.IGNORECASE),
            re.compile(r"Page Not Found - Netlify", re.IGNORECASE),
        ],
        severity="CRITICAL",
        confidence="CONFIRMED",
        remediation="Claim the custom domain in your Netlify account or delete the dangling DNS CNAME record.",
    ),
    ServiceSignature(
        service_name="Vercel",
        cname_patterns=["vercel.app", "now.sh", "cname.vercel-dns.com"],
        body_patterns=[
            re.compile(r"404:\s*NOT_FOUND", re.IGNORECASE),
            re.compile(r"The deployment could not be found on Vercel", re.IGNORECASE),
        ],
        severity="CRITICAL",
        confidence="CONFIRMED",
        remediation="Attach the custom domain in Vercel project settings or remove the dangling CNAME record.",
    ),
    ServiceSignature(
        service_name="Firebase Hosting",
        cname_patterns=["firebaseapp.com", "web.app"],
        body_patterns=[
            re.compile(r"Site Not Found", re.IGNORECASE),
            re.compile(r"Firebase Hosting Setup", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Connect the domain in Firebase Console under Hosting or remove the DNS CNAME record.",
    ),
    ServiceSignature(
        service_name="GitLab Pages",
        cname_patterns=["gitlab.io"],
        body_patterns=[
            re.compile(r"The page you're looking for could not be found", re.IGNORECASE),
            re.compile(r"404 Not Found.*GitLab", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Verify domain ownership in GitLab Pages settings or remove the DNS CNAME pointing to gitlab.io.",
    ),
    ServiceSignature(
        service_name="Fly.io",
        cname_patterns=["fly.dev"],
        body_patterns=[
            re.compile(r"404 Not Found.*Fly\.io", re.IGNORECASE),
            re.compile(r"Fly\.io 404", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Allocate the hostname certificate in Fly.io dashboard or delete the dangling CNAME.",
    ),
    ServiceSignature(
        service_name="Render",
        cname_patterns=["onrender.com"],
        body_patterns=[
            re.compile(r"Not Found.*render", re.IGNORECASE),
            re.compile(r"This service does not exist", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Claim the custom domain in Render web service settings or remove the DNS record.",
    ),
    ServiceSignature(
        service_name="Shopify",
        cname_patterns=["myshopify.com"],
        body_patterns=[
            re.compile(r"Sorry, this shop is currently unavailable", re.IGNORECASE),
            re.compile(r"Only one step left to start selling", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Link the custom domain inside Shopify admin or delete the DNS CNAME record.",
    ),
    ServiceSignature(
        service_name="Fastly",
        cname_patterns=["fastly.net"],
        body_patterns=[
            re.compile(r"Fastly error:\s*unknown domain", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Configure the domain in Fastly dashboard or remove the DNS CNAME record.",
    ),
    ServiceSignature(
        service_name="Surge.sh",
        cname_patterns=["surge.sh"],
        body_patterns=[
            re.compile(r"project not found", re.IGNORECASE),
        ],
        severity="CRITICAL",
        confidence="CONFIRMED",
        remediation="Deploy an empty project to Surge with this domain or remove the DNS record.",
    ),
    ServiceSignature(
        service_name="Ghost",
        cname_patterns=["ghost.io"],
        body_patterns=[
            re.compile(r"The thing you were looking for is no longer here", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Connect domain in Ghost Admin or remove the DNS CNAME record.",
    ),
    ServiceSignature(
        service_name="ReadTheDocs",
        cname_patterns=["readthedocs.io"],
        body_patterns=[
            re.compile(r"is not hosted by Read the Docs", re.IGNORECASE),
            re.compile(r"unknown to Read the Docs", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Assign the domain to a project on ReadTheDocs or remove the DNS record.",
    ),
    ServiceSignature(
        service_name="Bitbucket",
        cname_patterns=["bitbucket.io"],
        body_patterns=[
            re.compile(r"Repository not found", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Create a matching Bitbucket repository or delete the DNS record.",
    ),
    ServiceSignature(
        service_name="Zendesk",
        cname_patterns=["zendesk.com"],
        body_patterns=[
            re.compile(r"Help Center Closed", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Remove the host mapping in Zendesk or delete the DNS CNAME.",
    ),
    ServiceSignature(
        service_name="Pantheon",
        cname_patterns=["pantheonsite.io"],
        body_patterns=[
            re.compile(r"The gods are wise, but do not know of the site which you seek", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Assign the domain in Pantheon Dashboard or delete the DNS CNAME.",
    ),
    ServiceSignature(
        service_name="Tumblr",
        cname_patterns=["domains.tumblr.com"],
        body_patterns=[
            re.compile(r"Whatever you were looking for doesn't seem to exist at this URL", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Configure custom domain in Tumblr blog settings or remove the DNS record.",
    ),
    ServiceSignature(
        service_name="WordPress.com",
        cname_patterns=["wordpress.com"],
        body_patterns=[
            re.compile(r"Do you want to register", re.IGNORECASE),
            re.compile(r"doesn&#8217;t exist", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Claim the WordPress blog or remove the DNS CNAME record.",
    ),
    ServiceSignature(
        service_name="Unbounce",
        cname_patterns=["unbouncepages.com"],
        body_patterns=[
            re.compile(r"The requested URL was not found on this server", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Add the domain in Unbounce settings or delete the DNS record.",
    ),
    ServiceSignature(
        service_name="Helpjuice",
        cname_patterns=["helpjuice.com"],
        body_patterns=[
            re.compile(r"We could not find what you're looking for", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Configure the custom domain in Helpjuice or remove the DNS record.",
    ),
    ServiceSignature(
        service_name="Cargo Collective",
        cname_patterns=["cargocollective.com", "cargo.site"],
        body_patterns=[
            re.compile(r"404 Not Found", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Assign domain in Cargo or remove DNS record.",
    ),
    ServiceSignature(
        service_name="Webflow",
        cname_patterns=["webflow.io", "proxy-ssl.webflow.com"],
        body_patterns=[
            re.compile(r"The page you are looking for doesn't exist or has been moved", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Assign custom domain in Webflow project settings or delete DNS record.",
    ),
    ServiceSignature(
        service_name="HubSpot",
        cname_patterns=["hubspot.net"],
        body_patterns=[
            re.compile(r"domain has been disabled or not yet been assigned to a portal", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Connect domain in HubSpot Settings or remove the DNS record.",
    ),
    ServiceSignature(
        service_name="Statuspage",
        cname_patterns=["statuspage.io"],
        body_patterns=[
            re.compile(r"You are seeing this page because this domain has not been configured", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Configure custom domain in Atlassian Statuspage or delete DNS record.",
    ),
    ServiceSignature(
        service_name="Kinsta",
        cname_patterns=["kinsta.cloud"],
        body_patterns=[
            re.compile(r"No Site Found", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Add the domain in MyKinsta dashboard or remove the DNS record.",
    ),
    ServiceSignature(
        service_name="Intercom",
        cname_patterns=["custom.intercom.help"],
        body_patterns=[
            re.compile(r"Uh oh, that page doesn't exist", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Connect domain in Intercom Help Center settings or remove DNS record.",
    ),
    ServiceSignature(
        service_name="Pingdom",
        cname_patterns=["stats.pingdom.com"],
        body_patterns=[
            re.compile(r"Public Report Not Activated", re.IGNORECASE),
        ],
        severity="MEDIUM",
        confidence="HIGH",
        remediation="Activate public report in Pingdom or remove DNS record.",
    ),
    ServiceSignature(
        service_name="UserVoice",
        cname_patterns=["uservoice.com"],
        body_patterns=[
            re.compile(r"This UserVoice instance does not exist!", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Configure custom domain in UserVoice or remove DNS record.",
    ),
    ServiceSignature(
        service_name="Strikingly",
        cname_patterns=["strikinglydns.com"],
        body_patterns=[
            re.compile(r"page not found", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Assign domain in Strikingly site settings or remove DNS record.",
    ),
    ServiceSignature(
        service_name="SmartJobBoard",
        cname_patterns=["smartjobboard.com"],
        body_patterns=[
            re.compile(r"This job board of is currently unavailable", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Assign domain in SmartJobBoard settings or delete DNS record.",
    ),
    ServiceSignature(
        service_name="Help Scout",
        cname_patterns=["helpscoutdocs.com"],
        body_patterns=[
            re.compile(r"No settings were found for this company:", re.IGNORECASE),
        ],
        severity="HIGH",
        confidence="HIGH",
        remediation="Configure custom domain in Help Scout Docs or remove DNS record.",
    ),
]


def match_signatures_detailed(body: str, cname: str | None = None) -> list[SignatureMatch]:
    """Scan response body and CNAME against known signatures, returning full match objects."""
    matches: list[SignatureMatch] = []

    # Check body patterns
    for sig in SIGNATURES:
        pattern = sig.matches_body(body)
        if pattern:
            matches.append(
                SignatureMatch(
                    service_name=sig.service_name,
                    reason=f"{sig.service_name} marker detected ({pattern.pattern})",
                    signature=sig,
                    severity=sig.severity,
                    confidence=sig.confidence,
                    remediation=sig.remediation,
                )
            )

    # If no body match but CNAME explicitly points to a provider known for dangling CNAME takeover
    if not matches and cname:
        for sig in SIGNATURES:
            cname_match = sig.matches_cname(cname)
            if cname_match:
                matches.append(
                    SignatureMatch(
                        service_name=sig.service_name,
                        reason=f"Points via CNAME to {cname} ({sig.service_name})",
                        signature=sig,
                        severity=sig.severity,
                        confidence="HIGH",
                        remediation=sig.remediation,
                    )
                )

    return matches


def match_signatures(body: str, cname: str | None = None) -> list[tuple[str, str]]:
    """Scan response body and CNAME against known signatures.

    Returns a list of (service_name, reason_description) for backwards compatibility.
    """
    detailed = match_signatures_detailed(body, cname=cname)
    return [(m.service_name, m.reason) for m in detailed]


def get_signature_by_name(service_name: str) -> ServiceSignature | None:
    """Retrieve signature metadata by service name."""
    for sig in SIGNATURES:
        if sig.service_name.lower() == service_name.lower():
            return sig
    return None
