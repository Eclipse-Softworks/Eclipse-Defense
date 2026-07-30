import unittest
from unittest.mock import patch

from scanner.rate_limit.checker import check_rate_limit


class _Response:
    def __init__(self, status_code, headers=None):
        self.status_code = status_code
        self.headers = headers or {}


class _Session:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.headers = {}

    def get(self, _url, **_kwargs):
        return next(self.responses)


class RateLimitCheckerTests(unittest.TestCase):
    @patch("scanner.rate_limit.checker.time.sleep")
    def test_records_enforced_rate_limit(self, _sleep):
        session = _Session([
            _Response(200, {"X-RateLimit-Remaining": "1"}),
            _Response(429, {"Retry-After": "60"}),
        ])

        with patch("scanner.rate_limit.checker.load_rate_limit_config") as config:
            config.return_value = {
                "request_count": 3,
                "inter_request_delay_seconds": 0.1,
                "rate_limit_status_codes": [429],
                "rate_limit_headers": ["x-ratelimit-remaining", "retry-after"],
            }
            results = check_rate_limit("https://example.test/api", session, timeout=1)

        self.assertTrue(results["rate_limit_applied"])
        self.assertEqual(results["limited_at_request"], 2)
        self.assertEqual(results["vulnerabilities"], [])

    @patch("scanner.rate_limit.checker.time.sleep")
    def test_missing_rate_limit_signals_do_not_create_a_finding(self, _sleep):
        session = _Session([_Response(200), _Response(200)])

        with patch("scanner.rate_limit.checker.load_rate_limit_config") as config:
            config.return_value = {
                "request_count": 2,
                "inter_request_delay_seconds": 0.1,
                "rate_limit_status_codes": [429],
                "rate_limit_headers": [],
            }
            results = check_rate_limit("https://example.test/api", session, timeout=1)

        self.assertFalse(results["rate_limit_applied"])
        self.assertTrue(results["inconclusive"])
        self.assertEqual(results["vulnerabilities"], [])


if __name__ == "__main__":
    unittest.main()
