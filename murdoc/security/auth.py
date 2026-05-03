"""Console authentication, SSO principals, and RBAC helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any

import jwt
from fastapi import Request
from jwt import PyJWKClient

from murdoc.security.config import (
    MURDOC_ADMIN_TOKEN,
    MURDOC_AUTH_MODE,
    MURDOC_AUTH_PROXY_EMAIL_HEADER,
    MURDOC_AUTH_PROXY_GROUPS_HEADER,
    MURDOC_AUTH_PROXY_USER_HEADER,
    MURDOC_OIDC_AUDIENCE,
    MURDOC_OIDC_GROUPS_CLAIM,
    MURDOC_OIDC_ISSUER,
    MURDOC_OIDC_JWKS_URL,
    MURDOC_RBAC_ADMIN_GROUPS,
    MURDOC_RBAC_OPERATOR_GROUPS,
    MURDOC_RBAC_VIEWER_GROUPS,
    constant_time_equals,
)


ROLE_LEVELS = {"viewer": 1, "operator": 2, "admin": 3}
CONSOLE_SESSION_COOKIE = "murdoc_console_session"
CONSOLE_SESSION_TTL_SECONDS = 8 * 60 * 60
_jwk_client: PyJWKClient | None = None


@dataclass(frozen=True)
class Principal:
    subject: str
    role: str = "viewer"
    email: str = ""
    groups: tuple[str, ...] = field(default_factory=tuple)
    auth_mode: str = "local"

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "role": self.role,
            "email": self.email,
            "groups": list(self.groups),
            "auth_mode": self.auth_mode,
        }


@dataclass(frozen=True)
class AuthResult:
    authenticated: bool
    principal: Principal | None = None
    reason: str = ""


def _configured_auth_mode() -> str:
    if MURDOC_AUTH_MODE in {"disabled", "local", "proxy", "oidc"}:
        return MURDOC_AUTH_MODE
    return "local"


def auth_mode_label() -> str:
    mode = _configured_auth_mode()
    if mode == "disabled":
        return "Development access"
    if mode == "proxy":
        return "Enterprise identity proxy"
    if mode == "oidc":
        return "Enterprise SSO"
    return "Console password"


def auth_required() -> bool:
    mode = _configured_auth_mode()
    if mode == "disabled":
        return False
    if mode == "local":
        return bool(MURDOC_ADMIN_TOKEN)
    return True


def _session_secret() -> str:
    return MURDOC_ADMIN_TOKEN or "murdoc-local-dev-session"


def _sign_session(payload: str) -> str:
    return hmac.new(_session_secret().encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def create_console_session(principal: Principal) -> str:
    payload = json.dumps(
        {
            "sub": principal.subject,
            "role": principal.role,
            "email": principal.email,
            "groups": list(principal.groups),
            "auth_mode": principal.auth_mode,
            "exp": int(time.time()) + CONSOLE_SESSION_TTL_SECONDS,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    encoded = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")
    return f"{encoded}.{_sign_session(encoded)}"


def decode_console_session(value: str) -> Principal | None:
    if "." not in value:
        return None
    encoded, supplied_sig = value.rsplit(".", 1)
    if not constant_time_equals(supplied_sig, _sign_session(encoded)):
        return None
    padded = encoded + ("=" * (-len(encoded) % 4))
    try:
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return None
    if int(payload.get("exp", 0)) < int(time.time()):
        return None
    return Principal(
        subject=str(payload.get("sub") or "admin"),
        role=str(payload.get("role") or "admin"),
        email=str(payload.get("email") or ""),
        groups=tuple(str(group) for group in payload.get("groups", []) if group),
        auth_mode=str(payload.get("auth_mode") or "local"),
    )


def role_for_groups(groups: list[str] | tuple[str, ...]) -> str:
    normalized = {group.strip() for group in groups if group and group.strip()}
    if normalized.intersection(MURDOC_RBAC_ADMIN_GROUPS):
        return "admin"
    if normalized.intersection(MURDOC_RBAC_OPERATOR_GROUPS):
        return "operator"
    if normalized.intersection(MURDOC_RBAC_VIEWER_GROUPS):
        return "viewer"
    return "viewer"


def has_role(principal: Principal | None, required_role: str) -> bool:
    if principal is None:
        return False
    return ROLE_LEVELS.get(principal.role, 0) >= ROLE_LEVELS.get(required_role, 3)


def local_admin_principal() -> Principal:
    return Principal(subject="admin", role="admin", auth_mode="local")


def authenticate_local_password(password: str) -> AuthResult:
    if not auth_required():
        return AuthResult(True, Principal(subject="local", role="admin", auth_mode="disabled"))
    if _configured_auth_mode() != "local":
        return AuthResult(False, reason="password sign-in is disabled")
    if not MURDOC_ADMIN_TOKEN:
        return AuthResult(True, Principal(subject="local", role="admin", auth_mode="local"))
    if constant_time_equals(password, MURDOC_ADMIN_TOKEN):
        return AuthResult(True, local_admin_principal())
    return AuthResult(False, reason="invalid credentials")


def principal_from_session(request: Request) -> Principal | None:
    return decode_console_session(request.cookies.get(CONSOLE_SESSION_COOKIE, ""))


def principal_from_admin_token(request: Request) -> Principal | None:
    if not MURDOC_ADMIN_TOKEN:
        return None
    supplied = request.headers.get("X-Murdoc-Admin-Token", "").strip()
    authorization = request.headers.get("Authorization", "").strip()
    if not supplied and authorization.startswith("Bearer "):
        supplied = authorization.removeprefix("Bearer ").strip()
    if supplied and constant_time_equals(supplied, MURDOC_ADMIN_TOKEN):
        return local_admin_principal()
    return None


def _groups_from_header(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.replace(";", ",").split(",") if item.strip())


def principal_from_proxy_headers(request: Request) -> Principal | None:
    if _configured_auth_mode() != "proxy":
        return None
    subject = request.headers.get(MURDOC_AUTH_PROXY_USER_HEADER, "").strip()
    email = request.headers.get(MURDOC_AUTH_PROXY_EMAIL_HEADER, "").strip()
    groups = _groups_from_header(request.headers.get(MURDOC_AUTH_PROXY_GROUPS_HEADER, ""))
    if not subject and email:
        subject = email
    if not subject:
        return None
    return Principal(
        subject=subject,
        role=role_for_groups(groups),
        email=email,
        groups=groups,
        auth_mode="proxy",
    )


def _bearer_token(request: Request) -> str:
    authorization = request.headers.get("Authorization", "").strip()
    if authorization.startswith("Bearer "):
        return authorization.removeprefix("Bearer ").strip()
    return ""


def principal_from_oidc_bearer(request: Request) -> Principal | None:
    global _jwk_client
    if _configured_auth_mode() != "oidc":
        return None
    token = _bearer_token(request)
    if not token or not MURDOC_OIDC_ISSUER or not MURDOC_OIDC_AUDIENCE:
        return None
    jwks_url = MURDOC_OIDC_JWKS_URL or MURDOC_OIDC_ISSUER.rstrip("/") + "/.well-known/jwks.json"
    if _jwk_client is None or _jwk_client.uri != jwks_url:
        _jwk_client = PyJWKClient(jwks_url)
    key = _jwk_client.get_signing_key_from_jwt(token).key
    payload = jwt.decode(
        token,
        key=key,
        algorithms=["RS256", "ES256"],
        audience=MURDOC_OIDC_AUDIENCE,
        issuer=MURDOC_OIDC_ISSUER,
    )
    groups_value = payload.get(MURDOC_OIDC_GROUPS_CLAIM, [])
    if isinstance(groups_value, str):
        groups = _groups_from_header(groups_value)
    else:
        groups = tuple(str(group) for group in groups_value if group)
    subject = str(payload.get("sub") or payload.get("preferred_username") or payload.get("email") or "")
    if not subject:
        return None
    return Principal(
        subject=subject,
        role=role_for_groups(groups),
        email=str(payload.get("email") or ""),
        groups=groups,
        auth_mode="oidc",
    )


def authenticate_request(request: Request) -> AuthResult:
    mode = _configured_auth_mode()
    if mode == "disabled" or not auth_required():
        return AuthResult(True, Principal(subject="local", role="admin", auth_mode=mode))

    for resolver in (
        principal_from_session,
        principal_from_admin_token,
        principal_from_proxy_headers,
        principal_from_oidc_bearer,
    ):
        try:
            principal = resolver(request)
        except jwt.PyJWTError as exc:
            return AuthResult(False, reason=str(exc))
        if principal is not None:
            return AuthResult(True, principal)
    return AuthResult(False, reason="authentication required")
