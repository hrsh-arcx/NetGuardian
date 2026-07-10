"""
netguardian.security.auth — Proxy Authentication (HTTP Basic)

Parses the Proxy-Authorization header from incoming requests and
validates credentials against the configured user list.
"""

from __future__ import annotations

import base64
from typing import Dict, Optional, Tuple

from netguardian.telemetry.logger import get_logger

_log = get_logger("netguardian.security.auth")


class ProxyAuthenticator:
    """
    HTTP Basic proxy authentication.

    When enabled, clients must send a Proxy-Authorization header:
        Proxy-Authorization: Basic base64(username:password)
    """

    def __init__(self, users: Optional[Dict[str, str]] = None, enabled: bool = False):
        self._enabled = enabled
        self._users = users or {}

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    def authenticate(self, proxy_auth_header: Optional[str]) -> Tuple[bool, Optional[str]]:
        """
        Validate the Proxy-Authorization header.
        Returns (success, username) — username is None on failure.
        """
        if not self._enabled:
            return True, None

        if not proxy_auth_header:
            return False, None

        try:
            scheme, encoded = proxy_auth_header.strip().split(" ", 1)
            if scheme.lower() != "basic":
                return False, None

            decoded = base64.b64decode(encoded).decode("utf-8")
            username, password = decoded.split(":", 1)

            if username in self._users and self._users[username] == password:
                _log.debug(f"Auth success for user: {username}")
                return True, username

            _log.warning(f"Auth failed for user: {username}")
            return False, None

        except Exception:
            _log.warning("Malformed Proxy-Authorization header")
            return False, None

    def build_407_response(self) -> bytes:
        """Build a 407 Proxy Authentication Required response."""
        body = b"407 Proxy Authentication Required\n"
        return (
            b"HTTP/1.1 407 Proxy Authentication Required\r\n"
            b"Proxy-Authenticate: Basic realm=\"NetGuardian Proxy\"\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Content-Type: text/plain\r\n"
            b"Connection: close\r\n"
            b"\r\n" + body
        )
