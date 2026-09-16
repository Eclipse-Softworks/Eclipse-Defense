import unittest

from scanner.file_overwrite_checker import _check_backup_files


class _Response:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


class _Session:
    def get(self, url, **_kwargs):
        if url.endswith("/.env"):
            return _Response(200, "DATABASE_PASSWORD=example-secret")
        return _Response(404, "not found")


class BackupFileReportingTests(unittest.TestCase):
    def test_sensitive_file_exposure_sets_found_state(self):
        results = {"sensitive_file_found": False, "vulnerabilities": []}

        _check_backup_files("https://example.test", _Session(), results, timeout=1)

        self.assertTrue(results["sensitive_file_found"])
        self.assertEqual(
            results["vulnerabilities"][0]["type"], "Sensitive File Exposure"
        )


if __name__ == "__main__":
    unittest.main()
