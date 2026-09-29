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
    read_hostnames,
    scan_hostnames,
    write_results,
)
from src.dns_resolver import DnsLookupResult
from src.exporter import Finding, export_findings, format_csv, format_json, format_text
from src.signatures import SIGNATURES, match_signatures


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


if __name__ == "__main__":
    unittest.main()
