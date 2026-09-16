import unittest

from scanner.rce_checker import check_rce


class _Response:
    def __init__(self, text, status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _Session:
    def __init__(self, probe_payload):
        # probe_payload is the payload string that will be used to trigger a match
        self.probe_payload = probe_payload
        self.headers = {}

    def get(self, url, params=None, **_kwargs):
        # If the params include the probe payload, return a body that matches the RCE pattern
        if params and any(self.probe_payload == v for v in (params.values())):
            return _Response("uid=1000(root) gid=1000(root)")
        # For header-based log4shell tests, the rce_checker sends header payloads directly
        return _Response("normal page content")


class RceCheckerTests(unittest.TestCase):
    def test_detects_basic_unix_command_injection_from_query(self):
        # Patch the loader by creating a minimal config via monkeypatching the module import
        import scanner.rce_checker as rce_mod

        rce_mod.load_rce_config = lambda: {
            "rce_payloads": [
                {"name": "Basic Unix command injection (semicolon)", "payload": ";id", "pattern": "uid=\\d+", "severity": "CRITICAL"}
            ],
            "common_query_params": ["q"]
        }

        session = _Session(";id")
        results = check_rce("https://example.test/?q=test", session, timeout=1)

        self.assertTrue(results["rce_found"] or results["vulnerabilities"])
        self.assertTrue(any("Basic Unix" in v.get("type") or "Basic Unix" in v.get("type", "") for v in results.get("vulnerabilities", [])))


if __name__ == "__main__":
    unittest.main()
