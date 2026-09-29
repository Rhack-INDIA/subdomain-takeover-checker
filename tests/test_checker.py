import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import requests

from src.checker import (
    check_hostname,
    is_name_not_found,
    normalize_hostname,
    parse_args,
    parse_custom_headers,
    read_hostnames,
    scan_hostnames,
    write_results,
)
from src.discovery import (
    clean_domain,
    enumerate_subdomains,
    query_crt_sh,
    query_hackertarget,
    save_discovered_subdomains,
)
from src.dns_resolver import DnsLookupResult
from src.exporter import (
    Finding,
    export_findings,
    format_csv,
    format_html,
    format_json,
    format_text,
)
from src.signatures import SIGNATURES, match_signatures, match_signatures_detailed


class HostnameValidationTests(unittest.TestCase):
    def test_normalizes_valid_hostname(self):
        self.assertEqual(normalize_hostname(" WWW.Example.COM. "), "www.example.com")

    def test_rejects_url_and_single_label(self):
        for value in ("https://example.com", "localhost", "-bad.example.com"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_hostname(value)

    def test_reads_comments_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hosts.txt"
            path.write_text("# comment\nExample.com\nexample.com\n", encoding="utf-8")
            self.assertEqual(read_hostnames(path), ["example.com"])


class DetectionTests(unittest.TestCase):
    def test_nxdomain_becomes_candidate(self):
        dns_res = DnsLookupResult(hostname="missing.example.invalid", is_nxdomain=True)
        with patch("src.checker.resolve_domain", return_value=dns_res):
            self.assertEqual(
                check_hostname("missing.example.invalid", 1),
                [("missing.example.invalid", "NXDOMAIN candidate")],
            )

    def test_nxdomain_with_dangling_cname_identified(self):
        dns_res = DnsLookupResult(
            hostname="sub.example.com",
            is_nxdomain=True,
            canonical_cname="app.herokuapp.com",
        )
        with patch("src.checker.resolve_domain", return_value=dns_res):
            findings = check_hostname("sub.example.com", 1)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].service, "Heroku")
            self.assertIn("dangling CNAME to Heroku", findings[0].reason)

    def test_dns_error_is_not_a_candidate(self):
        dns_res = DnsLookupResult(
            hostname="host.example.com",
            is_nxdomain=False,
            error="DNS lookup timeout",
        )
        with patch("src.checker.resolve_domain", return_value=dns_res):
            self.assertEqual(check_hostname("host.example.com", 1), [])

    def test_no_such_bucket_response_becomes_candidate(self):
        dns_res = DnsLookupResult(
            hostname="bucket.example.com",
            ip_addresses=["1.2.3.4"],
        )
        response = Mock(status_code=404, text="<Code>NoSuchBucket</Code>")
        with (
            patch("src.checker.resolve_domain", return_value=dns_res),
            patch("src.checker.requests.get", return_value=response) as get,
        ):
            findings = check_hostname("bucket.example.com", 1)
            self.assertEqual(
                findings,
                [("bucket.example.com", "NoSuchBucket marker (404)")],
            )
            self.assertEqual(findings[0].service, "AWS S3")
            get.assert_called_once()
            self.assertTrue(get.call_args.args[0].startswith("https://"))

    def test_github_pages_detection(self):
        dns_res = DnsLookupResult(
            hostname="docs.example.com",
            canonical_cname="owner.github.io",
            ip_addresses=["185.199.108.153"],
        )
        response = Mock(
            status_code=404,
            text="<html><body>There isn't a GitHub Pages site here.</body></html>",
        )
        with (
            patch("src.checker.resolve_domain", return_value=dns_res),
            patch("src.checker.requests.get", return_value=response),
        ):
            findings = check_hostname("docs.example.com", 1)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].service, "GitHub Pages")
            self.assertIn("GitHub Pages marker (404)", findings[0].reason)

    def test_heroku_detection(self):
        dns_res = DnsLookupResult(
            hostname="api.example.com",
            canonical_cname="app.herokuapp.com",
            ip_addresses=["54.1.2.3"],
        )
        response = Mock(
            status_code=404,
            text="<title>No such app</title><body>There's nothing here, yet.</body>",
        )
        with (
            patch("src.checker.resolve_domain", return_value=dns_res),
            patch("src.checker.requests.get", return_value=response),
        ):
            findings = check_hostname("api.example.com", 1)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].service, "Heroku")

    def test_azure_detection(self):
        dns_res = DnsLookupResult(
            hostname="portal.example.com",
            canonical_cname="portal.azurewebsites.net",
            ip_addresses=["13.1.2.3"],
        )
        response = Mock(
            status_code=404,
            text="<h2>404 Web Site not found</h2>",
        )
        with (
            patch("src.checker.resolve_domain", return_value=dns_res),
            patch("src.checker.requests.get", return_value=response),
        ):
            findings = check_hostname("portal.example.com", 1)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].service, "Microsoft Azure")

    def test_cloudflare_detection(self):
        dns_res = DnsLookupResult(
            hostname="cdn.example.com",
            canonical_cname="custom.cloudflare.net",
            ip_addresses=["104.16.1.1"],
        )
        response = Mock(
            status_code=522,
            text="Error 1016: Origin DNS error",
        )
        with (
            patch("src.checker.resolve_domain", return_value=dns_res),
            patch("src.checker.requests.get", return_value=response),
        ):
            findings = check_hostname("cdn.example.com", 1)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].service, "Cloudflare")

    def test_netlify_detection(self):
        dns_res = DnsLookupResult(
            hostname="site.example.com",
            canonical_cname="site.netlify.app",
            ip_addresses=["35.1.2.3"],
        )
        response = Mock(
            status_code=404,
            text="<h1>Not Found - Request ID: 12345</h1>",
        )
        with (
            patch("src.checker.resolve_domain", return_value=dns_res),
            patch("src.checker.requests.get", return_value=response),
        ):
            findings = check_hostname("site.example.com", 1)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].service, "Netlify")

    def test_vercel_detection(self):
        dns_res = DnsLookupResult(
            hostname="app.example.com",
            canonical_cname="cname.vercel-dns.com",
            ip_addresses=["76.76.21.21"],
        )
        response = Mock(
            status_code=404,
            text="<div>404: NOT_FOUND</div><p>The deployment could not be found on Vercel</p>",
        )
        with (
            patch("src.checker.resolve_domain", return_value=dns_res),
            patch("src.checker.requests.get", return_value=response),
        ):
            findings = check_hostname("app.example.com", 1)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].service, "Vercel")

    def test_firebase_detection(self):
        dns_res = DnsLookupResult(
            hostname="auth.example.com",
            canonical_cname="auth.firebaseapp.com",
            ip_addresses=["199.36.158.100"],
        )
        response = Mock(
            status_code=404,
            text="<title>Site Not Found</title>",
        )
        with (
            patch("src.checker.resolve_domain", return_value=dns_res),
            patch("src.checker.requests.get", return_value=response),
        ):
            findings = check_hostname("auth.example.com", 1)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].service, "Firebase Hosting")

    def test_gitlab_pages_detection(self):
        dns_res = DnsLookupResult(
            hostname="gitdocs.example.com",
            canonical_cname="project.gitlab.io",
            ip_addresses=["35.185.44.232"],
        )
        response = Mock(
            status_code=404,
            text="The page you're looking for could not be found",
        )
        with (
            patch("src.checker.resolve_domain", return_value=dns_res),
            patch("src.checker.requests.get", return_value=response),
        ):
            findings = check_hostname("gitdocs.example.com", 1)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].service, "GitLab Pages")

    def test_http_error_is_logged_and_other_scheme_checked(self):
        dns_res = DnsLookupResult(
            hostname="host.example.com",
            ip_addresses=["1.2.3.4"],
        )
        response = Mock(status_code=200, text="ordinary page")
        with (
            patch("src.checker.resolve_domain", return_value=dns_res),
            patch(
                "src.checker.requests.get",
                side_effect=[requests.Timeout("timed out"), response],
            ) as get,
            self.assertLogs("takeover_checker", level="WARNING"),
        ):
            self.assertEqual(check_hostname("host.example.com", 1), [])
            self.assertEqual(get.call_count, 2)


class NetworkOptionsTests(unittest.TestCase):
    def test_check_hostname_with_proxy_and_headers(self):
        dns_res = DnsLookupResult(hostname="app.example.com", ip_addresses=["1.2.3.4"])
        mock_response = Mock(status_code=200, text="ok")
        with (
            patch("src.checker.resolve_domain", return_value=dns_res),
            patch("src.checker.requests.get", return_value=mock_response) as mock_get,
        ):
            check_hostname(
                "app.example.com",
                timeout=2.0,
                proxy="http://127.0.0.1:8080",
                custom_headers={"X-Test-Header": "Antigravity"},
            )
            self.assertTrue(mock_get.called)
            call_kwargs = mock_get.call_args[1]
            self.assertEqual(call_kwargs["proxies"], {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"})
            self.assertEqual(call_kwargs["headers"]["X-Test-Header"], "Antigravity")

    def test_check_hostname_with_retries(self):
        dns_res = DnsLookupResult(hostname="retry.example.com", ip_addresses=["1.2.3.4"])
        mock_response = Mock(status_code=404, text="<Code>NoSuchBucket</Code>")
        with (
            patch("src.checker.resolve_domain", return_value=dns_res),
            patch(
                "src.checker.requests.get",
                side_effect=[requests.ConnectionError("fail1"), mock_response],
            ) as mock_get,
        ):
            findings = check_hostname("retry.example.com", timeout=1.0, retries=1)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].service, "AWS S3")


class DiscoveryTests(unittest.TestCase):
    def test_clean_domain_valid(self):
        self.assertEqual(clean_domain("example.com"), "example.com")
        self.assertEqual(clean_domain("https://sub.example.com:8443/test/path"), "sub.example.com")
        self.assertEqual(clean_domain("WWW.TARGET.ORG."), "www.target.org")

    def test_clean_domain_invalid(self):
        for bad in ("", "invalid", "http://", "a..b.com"):
            with self.assertRaises(ValueError):
                clean_domain(bad)

    def test_query_crt_sh(self):
        mock_response = Mock(
            status_code=200,
            json=lambda: [
                {"name_value": "api.example.com\n*.dev.example.com"},
                {"name_value": "docs.example.com"},
                {"name_value": "othercorp.com"},  # Out of scope
            ],
        )
        with patch("src.discovery.requests.get", return_value=mock_response):
            subs = query_crt_sh("example.com", timeout=3.0)
            self.assertIn("api.example.com", subs)
            self.assertIn("dev.example.com", subs)
            self.assertIn("docs.example.com", subs)
            self.assertNotIn("othercorp.com", subs)

    def test_query_hackertarget(self):
        mock_response = Mock(
            status_code=200,
            text="portal.example.com,1.2.3.4\nmail.example.com,5.6.7.8\n",
        )
        with patch("src.discovery.requests.get", return_value=mock_response):
            subs = query_hackertarget("example.com", timeout=3.0)
            self.assertIn("portal.example.com", subs)
            self.assertIn("mail.example.com", subs)

    def test_enumerate_subdomains_integration(self):
        with (
            patch("src.discovery.query_crt_sh", return_value={"sub1.example.com"}),
            patch("src.discovery.query_hackertarget", return_value={"sub2.example.com"}),
        ):
            results = enumerate_subdomains("example.com")
            self.assertEqual(results, ["sub1.example.com", "sub2.example.com"])

    def test_save_discovered_subdomains(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            out_file = Path(temp_dir) / "discovered.txt"
            count = save_discovered_subdomains(out_file, ["a.example.com", "b.example.com"])
            self.assertEqual(count, 2)
            content = out_file.read_text(encoding="utf-8")
            self.assertEqual(content, "a.example.com\nb.example.com\n")


class ExporterTests(unittest.TestCase):
    def setUp(self):
        self.sample_findings = [
            Finding(
                hostname="s3.example.com",
                service="AWS S3",
                cname="bucket.s3.amazonaws.com",
                reason="NoSuchBucket marker (404)",
                status_code=404,
                timestamp="2026-09-29T12:00:00Z",
            ),
            Finding(
                hostname="missing.example.com",
                service=None,
                cname=None,
                reason="NXDOMAIN candidate",
                timestamp="2026-09-29T12:00:00Z",
            ),
        ]

    def test_format_json(self):
        json_str = format_json(self.sample_findings)
        data = json.loads(json_str)
        self.assertEqual(len(data), 2)
        self.assertEqual(data[0]["service"], "AWS S3")
        self.assertEqual(data[0]["status_code"], 404)

    def test_format_csv(self):
        csv_str = format_csv(self.sample_findings)
        self.assertIn("hostname,service,cname,reason,status_code,timestamp", csv_str)
        self.assertIn("s3.example.com,AWS S3,bucket.s3.amazonaws.com", csv_str)

    def test_format_html(self):
        html_str = format_html(self.sample_findings, report_title="Test Assessment")
        self.assertIn("<!DOCTYPE html>", html_str)
        self.assertIn("Test Assessment", html_str)
        self.assertIn("s3.example.com", html_str)
        self.assertIn("AWS S3", html_str)
        self.assertIn("badge-critical", html_str)
        self.assertIn("id=\"findingsTable\"", html_str)
        self.assertIn("filterSeverity", html_str)

    def test_writes_output_legacy_format(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "nested" / "targets.txt"
            count = write_results(output, [("host.example.com", "NXDOMAIN candidate")], export_format="legacy")
            self.assertEqual(count, 1)
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "host.example.com\tNXDOMAIN candidate\n",
            )

    def test_writes_output_json_format(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "results.json"
            count = write_results(output, self.sample_findings, export_format="json")
            self.assertEqual(count, 2)
            loaded = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(len(loaded), 2)

    def test_writes_output_html_format(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.html"
            count = write_results(output, self.sample_findings, export_format="html")
            self.assertEqual(count, 2)
            content = output.read_text(encoding="utf-8")
            self.assertIn("<!DOCTYPE html>", content)
            self.assertIn("AWS S3", content)


class ConcurrencyTests(unittest.TestCase):
    def test_scan_hostnames_multithreaded(self):
        hosts = [f"host{i}.example.com" for i in range(5)]
        dummy_finding = Finding(hostname="test.example.com", reason="test")
        with patch("src.checker.check_hostname", return_value=[dummy_finding]) as mock_check:
            results = scan_hostnames(hosts, threads=4, timeout=1.0)
            self.assertEqual(len(results), 5)
            self.assertEqual(mock_check.call_count, 5)


class CliTests(unittest.TestCase):
    def test_parse_args_defaults(self):
        args = parse_args([])
        self.assertEqual(args.threads, 10)
        self.assertEqual(args.timeout, 5.0)
        self.assertEqual(args.format, "text")

    def test_parse_args_custom(self):
        args = parse_args(["-t", "25", "-w", "2.5", "-f", "json", "-k", "-v"])
        self.assertEqual(args.threads, 25)
        self.assertEqual(args.timeout, 2.5)
        self.assertEqual(args.format, "json")
        self.assertTrue(args.no_verify_ssl)
        self.assertTrue(args.verbose)

    def test_parse_args_domain_and_proxy(self):
        args = parse_args([
            "-d", "example.com",
            "--save-subdomains", "subs.txt",
            "-p", "http://127.0.0.1:8080",
            "-H", "X-Custom: 123",
            "--delay", "0.5",
            "-r", "2",
            "--no-color",
            "-f", "html",
        ])
        self.assertEqual(args.domain, "example.com")
        self.assertEqual(str(args.save_subdomains), "subs.txt")
        self.assertEqual(args.proxy, "http://127.0.0.1:8080")
        self.assertEqual(args.headers, ["X-Custom: 123"])
        self.assertEqual(args.delay, 0.5)
        self.assertEqual(args.retries, 2)
        self.assertTrue(args.no_color)
        self.assertEqual(args.format, "html")

    def test_parse_args_fix_script(self):
        args = parse_args(["--fix-script", "fix.sh"])
        self.assertEqual(str(args.fix_script), "fix.sh")


class RemediationTests(unittest.TestCase):
    def setUp(self):
        self.sample_findings = [
            Finding(
                hostname="assets.example.com",
                service="AWS S3",
                cname="assets.s3.amazonaws.com",
                reason="NoSuchBucket marker (404)",
                status_code=404,
                remediation="Claim bucket or delete CNAME.",
            )
        ]

    def test_route53_remediation(self):
        from src.remediation import generate_aws_route53_remediation
        script = generate_aws_route53_remediation(self.sample_findings, hosted_zone_id="Z12345")
        self.assertIn("Z12345", script)
        self.assertIn("assets.example.com.", script)
        self.assertIn("DELETE", script)

    def test_cloudflare_remediation(self):
        from src.remediation import generate_cloudflare_remediation
        script = generate_cloudflare_remediation(self.sample_findings)
        self.assertIn("assets.example.com", script)
        self.assertIn("CF_API_TOKEN", script)
        self.assertIn("curl", script)

    def test_bind_remediation(self):
        from src.remediation import generate_bind_remediation
        script = generate_bind_remediation(self.sample_findings)
        self.assertIn("assets.example.com.", script)
        self.assertIn("CNAME", script)

    def test_export_remediation_playbook(self):
        from src.remediation import export_remediation_playbook
        with tempfile.TemporaryDirectory() as temp_dir:
            out_file = Path(temp_dir) / "remediation.sh"
            export_remediation_playbook(out_file, self.sample_findings)
            self.assertTrue(out_file.exists())
            content = out_file.read_text(encoding="utf-8")
            self.assertIn("AWS Route 53", content)
            self.assertIn("Cloudflare", content)
            self.assertIn("BIND", content)


if __name__ == "__main__":
    unittest.main()

