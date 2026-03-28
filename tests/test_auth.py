from __future__ import annotations

import unittest
from unittest.mock import patch

from tests._helpers import load_module


MODULE = load_module("services/shared/auth.py", "shared_auth_main")


class AuthTests(unittest.TestCase):
    def test_role_from_claims_maps_operator_and_admin_roles(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "DASHBOARD_OPERATOR_ROLE": "ops",
                "DASHBOARD_ADMIN_ROLE": "cluster-admin",
            },
            clear=False,
        ):
            self.assertEqual(MODULE.role_from_claims({"roles": ["ops"]}), "operator")
            self.assertEqual(MODULE.role_from_claims({"roles": ["cluster-admin"]}), "admin")

    def test_bearer_principal_and_role_uses_claims(self) -> None:
        with patch.object(MODULE, "decode_bearer_token", return_value={"sub": "alice", "roles": ["admin"]}):
            principal, role = MODULE.bearer_principal_and_role("Bearer token-value")

        self.assertEqual(principal, "alice")
        self.assertEqual(role, "admin")


if __name__ == "__main__":
    unittest.main()
