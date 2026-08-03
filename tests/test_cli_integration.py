import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import main


class CliIntegrationTests(unittest.TestCase):
    @patch("main.setup_logging")
    @patch("main.apply_runtime_profile")
    @patch("main.run_recon_phase")
    def test_recon_only_writes_json_artifact(self, mock_recon, mock_profile, _mock_logging):
        mock_profile.return_value = {"timeout_seconds": 5}
        mock_recon.return_value = {"domain": "example.com", "subdomains": ["www.example.com"]}
        with tempfile.TemporaryDirectory() as tmpdir:
            out = io.StringIO()
            argv = ["main.py", "example.com", "--recon-only", "--output", tmpdir]
            with patch("sys.argv", argv), redirect_stdout(out):
                rc = main.main()

            self.assertEqual(rc, 0)
            artifact = Path(tmpdir) / "recon_results.json"
            self.assertTrue(artifact.exists())
            self.assertIn('"domain": "example.com"', out.getvalue())
            mock_profile.assert_called_once_with("standard")

    @patch("main.setup_logging")
    @patch("main.run_cve_phase")
    @patch("main.run_recon_phase")
    def test_cve_only_writes_both_phase_artifacts(self, mock_recon, mock_cve, _mock_logging):
        mock_recon.return_value = {"domain": "example.com", "fingerprints": {}}
        mock_cve.return_value = {"jenkins": [{"cve_id": "CVE-2024-23897", "cvss": 9.1}]}
        with tempfile.TemporaryDirectory() as tmpdir:
            out = io.StringIO()
            argv = ["main.py", "example.com", "--cve-only", "--output", tmpdir]
            with patch("sys.argv", argv), redirect_stdout(out):
                rc = main.main()

            self.assertEqual(rc, 0)
            self.assertTrue((Path(tmpdir) / "recon_results.json").exists())
            self.assertTrue((Path(tmpdir) / "vulnerability_results.json").exists())
            payload = json.loads((Path(tmpdir) / "vulnerability_results.json").read_text(encoding="utf-8"))
            self.assertIn("jenkins", payload)

    @patch("main.setup_logging")
    @patch("main.assess_risk")
    def test_risk_only_uses_saved_inputs(self, mock_assess_risk, _mock_logging):
        mock_assess_risk.return_value = {
            "dashboard": {"remediation_roadmap": {}, "summary": {}, "risk_matrix": {"points": [], "zones": {"RED": []}}},
            "assets": [],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            (out_dir / "recon_results.json").write_text(json.dumps({"domain": "example.com", "fingerprints": {}}), encoding="utf-8")
            (out_dir / "vulnerability_results.json").write_text(json.dumps({}), encoding="utf-8")

            argv = ["main.py", "example.com", "--risk-only", "--output", tmpdir, "--output-format", "json"]
            with patch("sys.argv", argv):
                rc = main.main()

            self.assertEqual(rc, 0)
            self.assertTrue((out_dir / "risk_assessment.json").exists())
            self.assertTrue((out_dir / "executive_summary.json").exists())
            self.assertEqual(mock_assess_risk.call_count, 1)

    @patch("main.setup_logging")
    @patch("main.assess_risk")
    @patch("main.run_cve_phase")
    @patch("main.run_recon_phase")
    def test_offline_data_skips_live_recon_and_cve(self, mock_recon, mock_cve, mock_assess_risk, _mock_logging):
        mock_assess_risk.return_value = {
            "domain": "example.com",
            "dashboard": {"remediation_roadmap": {}, "summary": {}, "risk_matrix": {"points": [], "zones": {"RED": []}}},
            "assets": [],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            fixture = {
                "recon_results": {"domain": "example.com", "fingerprints": {}},
                "vulnerability_results": {},
            }
            fixture_path = out_dir / "fixture.json"
            fixture_path.write_text(json.dumps(fixture), encoding="utf-8")

            argv = ["main.py", "example.com", "--offline-data", str(fixture_path), "--output", tmpdir, "--output-format", "json"]
            with patch("sys.argv", argv):
                rc = main.main()

            self.assertEqual(rc, 0)
            self.assertEqual(mock_recon.call_count, 0)
            self.assertEqual(mock_cve.call_count, 0)
            self.assertTrue((out_dir / "risk_assessment.json").exists())

    @patch("main.setup_logging")
    @patch("main.apply_runtime_profile")
    def test_invalid_target_is_rejected(self, _mock_profile, _mock_logging):
        argv = ["main.py", "not_a_domain", "--recon-only"]
        with patch("sys.argv", argv):
            with self.assertRaises(ValueError):
                main.main()


if __name__ == "__main__":
    unittest.main()
