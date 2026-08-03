import json
import tempfile
import unittest
from pathlib import Path

import config
from utils import apply_config_file_overrides, apply_env_file_overrides, apply_runtime_profile


class RuntimeOverrideTests(unittest.TestCase):
    def setUp(self):
        self.original = {
            "REQUEST_TIMEOUT_SECONDS": config.REQUEST_TIMEOUT_SECONDS,
            "RETRY_ATTEMPTS": config.RETRY_ATTEMPTS,
            "RETRY_BACKOFF_SECONDS": config.RETRY_BACKOFF_SECONDS,
            "NVD_API_KEY": config.NVD_API_KEY,
        }

    def tearDown(self):
        config.REQUEST_TIMEOUT_SECONDS = self.original["REQUEST_TIMEOUT_SECONDS"]
        config.RETRY_ATTEMPTS = self.original["RETRY_ATTEMPTS"]
        config.RETRY_BACKOFF_SECONDS = self.original["RETRY_BACKOFF_SECONDS"]
        config.NVD_API_KEY = self.original["NVD_API_KEY"]

    def test_precedence_profile_then_env_then_config_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env_path = Path(tmpdir) / ".env"
            json_path = Path(tmpdir) / "runtime_config.json"
            env_path.write_text(
                "REQUEST_TIMEOUT_SECONDS=6\nRETRY_ATTEMPTS=5\nNVD_API_KEY=env-key\n",
                encoding="utf-8",
            )
            json_path.write_text(
                json.dumps(
                    {
                        "request_timeout_seconds": 9,
                        "retry_attempts": 7,
                        "NVD_API_KEY": "json-key",
                    }
                ),
                encoding="utf-8",
            )

            apply_runtime_profile("quick")
            apply_env_file_overrides(str(env_path), required=True)
            apply_config_file_overrides(str(json_path))

            self.assertEqual(config.REQUEST_TIMEOUT_SECONDS, 9)
            self.assertEqual(config.RETRY_ATTEMPTS, 7)
            self.assertEqual(config.NVD_API_KEY, "json-key")

    def test_missing_optional_env_file_is_ignored(self):
        applied = apply_env_file_overrides("C:\\nonexistent\\.env", required=False)
        self.assertEqual(applied, {})


if __name__ == "__main__":
    unittest.main()
