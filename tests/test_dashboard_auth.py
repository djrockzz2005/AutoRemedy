from __future__ import annotations

from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests._helpers import load_module


class DashboardAuthTests(unittest.TestCase):
    def test_role_resolution_distinguishes_operator_and_admin_keys(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "DASHBOARD_OPERATOR_API_KEY": "operator-secret",
                "DASHBOARD_ADMIN_API_KEY": "admin-secret",
            },
            clear=False,
        ):
            module = load_module("services/dashboard/app/main.py", "dashboard_main")

        self.assertEqual(module.role_for_api_key("operator-secret"), "operator")
        self.assertEqual(module.role_for_api_key("admin-secret"), "admin")
        self.assertIsNone(module.role_for_api_key("wrong"))

    def test_dashboard_accepts_bearer_role_from_shared_auth(self) -> None:
        module = load_module("services/dashboard/app/main.py", "dashboard_main_bearer")
        with patch.object(module, "bearer_principal_and_role", return_value=("alice@example.com", "admin")):
            principal, role = module.bearer_principal_and_role("Bearer fake")
        self.assertEqual(principal, "alice@example.com")
        self.assertEqual(role, "admin")

    def test_csrf_token_round_trip(self) -> None:
        module = load_module("services/dashboard/app/main.py", "dashboard_main_csrf")
        token = module.csrf_token_value("operator")
        request = SimpleNamespace(headers={"x-csrf-token": token}, cookies={module.CSRF_COOKIE_NAME: token})

        self.assertTrue(module.validate_csrf_token(request, "operator"))

    def test_session_binding_id_extracts_signed_session_identifier(self) -> None:
        module = load_module("services/dashboard/app/main.py", "dashboard_main_session_binding")
        value = "operator:nonce:signature"

        self.assertEqual(module.session_binding_id(value), value)


if __name__ == "__main__":
    unittest.main()
