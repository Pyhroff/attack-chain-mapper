import unittest

from risk import assess_risk
from risk.asset_profiler import calculate_asset_risk_score, score_asset_criticality


class RiskModuleTests(unittest.TestCase):
    def test_asset_criticality_for_external_jenkins(self):
        data = {
            "asset": "jenkins.example.com",
            "tech_stack": [{"technology": "Jenkins"}],
            "is_external": True,
            "environment": "prod",
        }
        result = score_asset_criticality(data)
        self.assertEqual(result["criticality"], 9)

    def test_composite_risk_formula(self):
        criticality = {"asset": "jenkins.example.com", "criticality": 9}
        vulns = [{"cvss": 9.1}, {"cvss": 7.5}, {"cvss": 8.0}]
        result = calculate_asset_risk_score(criticality, vulns)
        self.assertAlmostEqual(result["risk_score"], 7.84, places=2)
        self.assertEqual(result["risk_level"], "HIGH")

    def test_assess_risk_prioritizes_jenkins_over_s3(self):
        recon = {
            "domain": "example.com",
            "fingerprints": {
                "jenkins.example.com": [
                    {
                        "http": {"status_code": 200, "headers": {"X-Jenkins": "2.404.1"}},
                        "https": {"status_code": 200, "headers": {"X-Jenkins": "2.404.1"}},
                        "tech_stack": [{"technology": "Jenkins", "version": "2.404.1"}],
                    }
                ],
                "files.s3.example.com": [
                    {
                        "http": {"status_code": 200, "headers": {}},
                        "https": {"status_code": 200, "headers": {}},
                        "tech_stack": [{"technology": "AWS S3", "version": "unknown"}],
                    }
                ],
            },
        }
        vuln = {
            "jenkins": [
                {
                    "cve_id": "CVE-2024-23897",
                    "software": "jenkins",
                    "version": "2.404.1",
                    "cvss": 9.1,
                    "patch_version": "2.405.1",
                    "priority": 9,
                }
            ]
        }
        out = assess_risk(recon, vuln, include_roadmap=True)
        self.assertEqual(out["assets"][0]["asset"], "jenkins.example.com")
        self.assertGreater(out["assets"][0]["risk_score"], out["assets"][1]["risk_score"])


if __name__ == "__main__":
    unittest.main()
