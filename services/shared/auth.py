from __future__ import annotations

import os
from typing import Any

import jwt


ROLE_OPERATOR = "operator"
ROLE_ADMIN = "admin"


def decode_bearer_token(token: str) -> dict[str, Any]:
    secret = os.getenv("DASHBOARD_JWT_SECRET", "")
    issuer = os.getenv("DASHBOARD_JWT_ISSUER", "")
    audience = os.getenv("DASHBOARD_JWT_AUDIENCE", "")
    options = {"verify_signature": bool(secret)}
    kwargs: dict[str, Any] = {"options": options, "algorithms": ["HS256", "RS256"]}
    if secret:
        kwargs["key"] = secret
    if issuer:
        kwargs["issuer"] = issuer
    if audience:
        kwargs["audience"] = audience
    payload = jwt.decode(token, **kwargs)
    return payload if isinstance(payload, dict) else {}


def principal_from_claims(claims: dict[str, Any]) -> str:
    return str(claims.get("email") or claims.get("preferred_username") or claims.get("sub") or "jwt-user")


def role_from_claims(claims: dict[str, Any]) -> str | None:
    raw_roles = claims.get("roles") or claims.get("role") or claims.get("groups") or []
    if isinstance(raw_roles, str):
        roles = {raw_roles}
    else:
        roles = {str(item) for item in raw_roles}
    admin_claim = os.getenv("DASHBOARD_ADMIN_ROLE", "admin")
    operator_claim = os.getenv("DASHBOARD_OPERATOR_ROLE", "operator")
    if admin_claim in roles:
        return ROLE_ADMIN
    if operator_claim in roles:
        return ROLE_OPERATOR
    return None


def bearer_principal_and_role(authorization: str | None) -> tuple[str | None, str | None]:
    if not authorization or not authorization.lower().startswith("bearer "):
        return None, None
    claims = decode_bearer_token(authorization.split(" ", 1)[1].strip())
    return principal_from_claims(claims), role_from_claims(claims)
