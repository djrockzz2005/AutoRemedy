from __future__ import annotations

import unittest

from tests._helpers import load_module


class DashboardSessionAuthTests(unittest.TestCase):
    def test_password_hash_round_trip(self) -> None:
        module = load_module("services/dashboard/app/main.py", "dashboard_main_session_hash")

        stored = module.password_hash("super-secret-password")

        self.assertTrue(module.verify_password("super-secret-password", stored))
        self.assertFalse(module.verify_password("wrong-password", stored))

    def test_session_cookie_round_trip(self) -> None:
        module = load_module("services/dashboard/app/main.py", "dashboard_main_session_cookie")

        cookie = module.session_cookie_value("operator")

        self.assertEqual(module.username_from_session(cookie), "operator")
        self.assertIsNone(module.username_from_session(f"{cookie}tampered"))


if __name__ == "__main__":
    unittest.main()
