import unittest
from unittest.mock import MagicMock, patch

from recon import subdomain_enum
from recon.fingerprinting import _detect_tech_stack


class ReconModuleTests(unittest.TestCase):
    def test_extract_subdomains_filters_invalid_entries(self):
        text = "www.example.com mail.example.com subjectname@example.com api.example.com"
        results = subdomain_enum._extract_subdomains_from_text(text, "example.com")
        self.assertIn("www.example.com", results)
        self.assertIn("api.example.com", results)
        self.assertNotIn("subjectname@example.com", results)

    @patch("recon.subdomain_enum.dns.resolver.resolve")
    def test_resolve_subdomains_skips_dead_hosts(self, mock_resolve):
        def fake_resolve(host, record_type):
            if host == "alive.example.com" and record_type == "A":
                return [MagicMock(to_text=lambda: "1.2.3.4")]
            raise Exception("not found")

        mock_resolve.side_effect = fake_resolve
        resolved = subdomain_enum.resolve_subdomains(["alive.example.com", "dead.example.com"])
        self.assertEqual(resolved["alive.example.com"], ["1.2.3.4"])
        self.assertNotIn("dead.example.com", resolved)

    @patch("recon.fingerprinting.requests.get")
    def test_detect_tech_stack_from_headers(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200)
        http_data = {"headers": {"Server": "nginx/1.21.3", "X-Jenkins": "2.404.1"}}
        https_data = {"headers": {}}
        findings = _detect_tech_stack("jenkins.example.com", http_data, https_data)
        names = {item["technology"] for item in findings}
        self.assertIn("nginx", names)
        self.assertIn("Docker Registry", names)


if __name__ == "__main__":
    unittest.main()
