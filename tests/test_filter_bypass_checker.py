import unittest

from scanner.filter_bypass_checker import check_filter_bypass


class _Response:
    def __init__(self, text, status_code=200, headers=None, url="https://example.test"):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}
        self.url = url


class _Session:
    def __init__(self, payload_to_reflect):
        self.payload_to_reflect = payload_to_reflect
        self.headers = {}

    def get(self, url, params=None, **_kwargs):
        # If a param contains payload, reflect it in the body
        body = "normal"
        if params:
            for v in params.values():
                if v == self.payload_to_reflect:
                    body = f"<script>{self.payload_to_reflect}</script>"
        return _Response(body)

    def post(self, url, data=None, headers=None, **_kwargs):
        body = ""
        if data and "eclipse_xss_probe_12345" in data:
            body = "<script>eclipse_xss_probe_12345</script>"
        return _Response(body)

    def options(self, url, **_kwargs):
        # Return no Allow header by default
        return _Response("", headers={})

    def request(self, method, url, **_kwargs):
        # Simulate TRACE method disabled by default
        if method.upper() == "TRACE":
            return _Response("", status_code=405)
        return _Response("")


class FilterBypassTests(unittest.TestCase):
    def test_detects_reflected_xss_via_query_param(self):
        import scanner.filter_bypass_checker as filter_mod

        filter_mod.load_filter_config = lambda: {
            "xss_payloads": ["<script>alert(1)</script>"],
            "client_filter_params": ["q"],
            "sql_injection_payloads": [],
            "sql_error_patterns": [],
        }

        session = _Session("<script>alert(1)</script>")
        results = check_filter_bypass(
            "https://example.test/?q=test", session, timeout=1
        )

        self.assertTrue(results["xss_found"] or results["vulnerabilities"])
        self.assertTrue(
            any(
                v["type"].startswith("Reflected XSS")
                or v["type"].startswith("Potential XSS")
                for v in results.get("vulnerabilities", [])
            )
        )


if __name__ == "__main__":
    unittest.main()
