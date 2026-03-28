from __future__ import annotations

import unittest

from tests._helpers import load_module


MODULE = load_module("services/api-gateway/app/main.py", "api_gateway_main")


class ApiGatewaySecurityTests(unittest.TestCase):
    def test_request_payload_text_includes_query_headers_and_body(self) -> None:
        request = type(
            "RequestStub",
            (),
            {
                "url": type("URLStub", (), {"query": "q=%3Cscript%3E"})(),
                "headers": {"origin": "http://localhost", "user-agent": "tester"},
            },
        )()

        text = MODULE.request_payload_text(b'{"x":"hello"}', request)

        self.assertIn("q=%3Cscript%3E", text)
        self.assertIn("origin:http://localhost", text)

    def test_client_ip_prefers_forwarded_for_header(self) -> None:
        request = type(
            "RequestStub",
            (),
            {
                "headers": {"x-forwarded-for": "203.0.113.10, 10.0.0.1"},
                "client": type("ClientStub", (), {"host": "10.0.0.2"})(),
            },
        )()

        self.assertEqual(MODULE.client_ip(request), "203.0.113.10")

    def test_suspicious_transport_or_network_detects_tls_downgrade(self) -> None:
        request = type(
            "RequestStub",
            (),
            {"headers": {"x-forwarded-proto": "http", "host": "localhost"}, "client": type("ClientStub", (), {"host": "127.0.0.1"})()},
        )()

        findings = MODULE.suspicious_transport_or_network(request)

        self.assertEqual(findings[0][1], "tls_downgrade_detected")


if __name__ == "__main__":
    unittest.main()
