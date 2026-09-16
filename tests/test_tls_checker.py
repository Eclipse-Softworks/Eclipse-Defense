import unittest

import scanner.tls_checker as tls_mod


class _MockSocket:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _MockTLSSock:
    def __init__(self, cert, proto, cipher):
        self._cert = cert
        self._proto = proto
        self._cipher = cipher

    def getpeercert(self):
        return self._cert

    def version(self):
        return self._proto

    def cipher(self):
        return self._cipher

    # Support context manager protocol used by wrap_socket usage
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class TlsCheckerTests(unittest.TestCase):
    def test_valid_certificate_and_cipher_are_reported(self):
        # Patch ssl.create_default_context and socket.create_connection
        cert = {
            "notAfter": "Dec 31 23:59:59 2099 GMT",
            "notBefore": "Jan 01 00:00:00 2020 GMT",
            "subjectAltName": [("DNS", "example.test")],
        }
        proto = "TLSv1.2"
        cipher = ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)

        original_create_default_context = tls_mod.ssl.create_default_context
        original_socket_conn = tls_mod.socket.create_connection

        try:

            class MockCtx:
                def wrap_socket(self, sock, server_hostname=None):
                    return _MockTLSSock(cert, proto, cipher)

            tls_mod.ssl.create_default_context = lambda: MockCtx()
            tls_mod.socket.create_connection = lambda *a, **k: _MockSocket()

            # Prevent the weak-protocol probing from attempting real socket ops
            tls_mod._check_weak_protocol_support = lambda *a, **k: None

            results = tls_mod.check_tls("https://example.test", timeout=1)
            self.assertIn("protocol", results)
            self.assertIn("cipher", results)
            self.assertTrue(results.get("protocol_safe", True))
        finally:
            tls_mod.ssl.create_default_context = original_create_default_context
            tls_mod.socket.create_connection = original_socket_conn
            # restore original helper if present
            tls_mod._check_weak_protocol_support = tls_mod._check_weak_protocol_support


if __name__ == "__main__":
    unittest.main()
