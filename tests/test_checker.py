import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from src.checker import check_hostname, is_name_not_found, normalize_hostname, read_hostnames, write_results


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
        error = socket.gaierror(socket.EAI_NONAME, "name not known")
        with patch("src.checker.socket.getaddrinfo", side_effect=error):
            self.assertEqual(check_hostname("missing.example.invalid", 1), [
                ("missing.example.invalid", "NXDOMAIN candidate")
            ])

    def test_temporary_dns_error_is_not_a_candidate(self):
        error = socket.gaierror(getattr(socket, "EAI_AGAIN", -3), "temporary failure")
        with patch("src.checker.socket.getaddrinfo", side_effect=error):
            self.assertEqual(check_hostname("host.example.com", 1), [])

    def test_no_such_bucket_response_becomes_candidate(self):
        response = Mock(status_code=404, text="<Code>NoSuchBucket</Code>")
        with (
            patch("src.checker.socket.getaddrinfo"),
            patch("src.checker.requests.get", return_value=response) as get,
        ):
            self.assertEqual(check_hostname("bucket.example.com", 1), [
                ("bucket.example.com", "NoSuchBucket marker (404)")
            ])
            get.assert_called_once()
            self.assertTrue(get.call_args.args[0].startswith("https://"))

    def test_http_error_is_logged_and_other_scheme_checked(self):
        response = Mock(status_code=200, text="ordinary page")
        with (
            patch("src.checker.socket.getaddrinfo"),
            patch(
                "src.checker.requests.get",
                side_effect=[requests.Timeout("timed out"), response],
            ) as get,
            self.assertLogs("takeover_checker", level="WARNING"),
        ):
            self.assertEqual(check_hostname("host.example.com", 1), [])
            self.assertEqual(get.call_count, 2)

    def test_writes_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "nested" / "targets.txt"
            count = write_results(output, [("host.example.com", "NXDOMAIN candidate")])
            self.assertEqual(count, 1)
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "host.example.com\tNXDOMAIN candidate\n",
            )

    def test_name_not_found_checks_resolver_codes(self):
        self.assertTrue(is_name_not_found(socket.gaierror(socket.EAI_NONAME, "missing")))


if __name__ == "__main__":
    unittest.main()
