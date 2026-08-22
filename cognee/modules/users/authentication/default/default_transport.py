import os
from fastapi_users.authentication import CookieTransport


def _cookie_flag(env_var: str, default: bool) -> bool:
    """Read a boolean cookie attribute from the environment."""
    value = os.getenv(env_var)
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


# Get cookie domain from environment variable.
# If not set or empty, no Domain attribute is emitted, which makes the cookie
# host-only: the browser sends it back only to the exact host that set it.
# Set AUTH_TOKEN_COOKIE_DOMAIN to share the cookie across subdomains.
cookie_domain = os.getenv("AUTH_TOKEN_COOKIE_DOMAIN")
if cookie_domain == "":
    cookie_domain = None

# SameSite/Secure have to be configurable for cross-origin deployments. When the
# UI is served from a different origin than the API (CORS_ALLOWED_ORIGINS with
# allow_credentials=True), browsers withhold a SameSite=Lax cookie from those
# requests, so login succeeds but every following request is unauthenticated.
# SameSite=None is the mode that permits it, and browsers reject SameSite=None
# unless Secure is also set -- hence the default below.
cookie_samesite = os.getenv("AUTH_TOKEN_COOKIE_SAMESITE") or "Lax"
if cookie_samesite.strip().lower() not in ("lax", "strict", "none"):
    raise ValueError(
        "AUTH_TOKEN_COOKIE_SAMESITE must be one of 'lax', 'strict' or 'none', "
        f"got {cookie_samesite!r}"
    )
cookie_secure = _cookie_flag("AUTH_TOKEN_COOKIE_SECURE", cookie_samesite.strip().lower() == "none")

# Note: Cookie expiration is automatically set by FastAPI Users based on JWT Strategy's lifetime_seconds
# The JWT Strategy lifetime_seconds is configured in get_client_auth_backend.py
# and reads from JWT_LIFETIME_SECONDS environment variable

default_transport = CookieTransport(
    cookie_name=os.getenv("AUTH_TOKEN_COOKIE_NAME", "auth_token"),
    cookie_secure=cookie_secure,
    cookie_httponly=True,
    cookie_samesite=cookie_samesite,
    cookie_domain=cookie_domain,
)

default_transport.name = "cookie"
