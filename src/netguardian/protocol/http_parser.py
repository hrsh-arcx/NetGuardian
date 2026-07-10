"""
netguardian.protocol.http_parser — Streaming HTTP/1.1 Parser

Incrementally parses raw bytes into structured HttpRequest / HttpResponse
objects. Handles the CONNECT method (for HTTPS tunneling), chunked
transfer-encoding, and common edge cases like missing Content-Length.
Zero external dependencies — pure stdlib.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote


@dataclass
class HttpRequest:
    """Parsed HTTP request."""
    method: str = ""
    uri: str = ""
    version: str = "HTTP/1.1"
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    raw_request_line: str = ""

    @property
    def host(self) -> str:
        """Extract target host from Host header or URI."""
        if "host" in self.headers:
            return self.headers["host"].split(":")[0]
        # For CONNECT requests, the URI is host:port
        if ":" in self.uri:
            return self.uri.split(":")[0]
        return self.uri

    @property
    def port(self) -> int:
        """Extract target port. Defaults to 443 for CONNECT, 80 otherwise."""
        # Check Host header first
        host_header = self.headers.get("host", "")
        if ":" in host_header:
            try:
                return int(host_header.rsplit(":", 1)[1])
            except ValueError:
                pass
        # CONNECT URI is always host:port
        if self.method == "CONNECT" and ":" in self.uri:
            try:
                return int(self.uri.rsplit(":", 1)[1])
            except ValueError:
                pass
        return 443 if self.method == "CONNECT" else 80

    @property
    def is_connect(self) -> bool:
        return self.method == "CONNECT"

    @property
    def content_length(self) -> Optional[int]:
        cl = self.headers.get("content-length")
        if cl is not None:
            try:
                return int(cl)
            except ValueError:
                return None
        return None

    @property
    def is_chunked(self) -> bool:
        return "chunked" in self.headers.get("transfer-encoding", "").lower()

    @property
    def decoded_uri(self) -> str:
        """URL-decoded URI for IDS inspection."""
        return unquote(self.uri)


@dataclass
class HttpResponse:
    """Parsed HTTP response."""
    version: str = "HTTP/1.1"
    status_code: int = 0
    reason: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    @property
    def content_length(self) -> Optional[int]:
        cl = self.headers.get("content-length")
        if cl is not None:
            try:
                return int(cl)
            except ValueError:
                return None
        return None

    @property
    def is_chunked(self) -> bool:
        return "chunked" in self.headers.get("transfer-encoding", "").lower()


class ParseError(Exception):
    """Raised when HTTP data is malformed."""
    pass


class HttpParser:
    """
    Incremental HTTP/1.1 parser.

    Feed it raw bytes and it produces HttpRequest or HttpResponse objects.
    Designed to work with asyncio stream readers — you read a chunk,
    feed it here, and check if a complete message is available.
    """

    MAX_REQUEST_LINE = 8192
    MAX_HEADER_SIZE = 65536
    MAX_HEADERS = 100

    def __init__(self):
        self._buffer = bytearray()

    def feed(self, data: bytes) -> None:
        """Append raw bytes to the internal buffer."""
        self._buffer.extend(data)

    def clear(self) -> None:
        """Reset the parser state."""
        self._buffer.clear()

    @property
    def buffered(self) -> int:
        return len(self._buffer)

    # ── Request Parsing ──

    def parse_request(self) -> Optional[HttpRequest]:
        """
        Try to parse a complete HTTP request from the buffer.
        Returns None if more data is needed.
        Raises ParseError on malformed input.
        """
        header_end = self._find_header_end()
        if header_end is None:
            if len(self._buffer) > self.MAX_HEADER_SIZE:
                raise ParseError("Request headers exceed maximum size")
            return None

        header_bytes = bytes(self._buffer[:header_end])
        try:
            header_text = header_bytes.decode("utf-8", errors="replace")
        except Exception:
            raise ParseError("Failed to decode request headers")

        lines = header_text.split("\r\n")
        if not lines or not lines[0]:
            raise ParseError("Empty request line")

        # Parse request line: METHOD URI HTTP/x.x
        request_line = lines[0]
        parts = request_line.split(" ", 2)
        if len(parts) < 2:
            raise ParseError(f"Malformed request line: {request_line!r}")

        method = parts[0].upper()
        uri = parts[1]
        version = parts[2] if len(parts) > 2 else "HTTP/1.1"

        if method not in (
            "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD",
            "OPTIONS", "CONNECT", "TRACE",
        ):
            raise ParseError(f"Unknown HTTP method: {method}")

        headers = self._parse_headers(lines[1:])

        req = HttpRequest(
            method=method,
            uri=uri,
            version=version,
            headers=headers,
            raw_request_line=request_line,
        )

        # Consume header bytes from buffer
        remaining = bytes(self._buffer[header_end:])
        self._buffer.clear()

        # Read body if present
        body, leftover = self._read_body(remaining, req.content_length, req.is_chunked)
        req.body = body

        # Put unconsumed data back
        self._buffer.extend(leftover)

        return req

    def parse_response(self) -> Optional[HttpResponse]:
        """
        Try to parse a complete HTTP response from the buffer.
        Returns None if more data is needed.
        """
        header_end = self._find_header_end()
        if header_end is None:
            if len(self._buffer) > self.MAX_HEADER_SIZE:
                raise ParseError("Response headers exceed maximum size")
            return None

        header_bytes = bytes(self._buffer[:header_end])
        try:
            header_text = header_bytes.decode("utf-8", errors="replace")
        except Exception:
            raise ParseError("Failed to decode response headers")

        lines = header_text.split("\r\n")
        if not lines or not lines[0]:
            raise ParseError("Empty status line")

        # Parse status line: HTTP/x.x STATUS REASON
        status_line = lines[0]
        parts = status_line.split(" ", 2)
        if len(parts) < 2:
            raise ParseError(f"Malformed status line: {status_line!r}")

        version = parts[0]
        try:
            status_code = int(parts[1])
        except ValueError:
            raise ParseError(f"Invalid status code: {parts[1]}")

        reason = parts[2] if len(parts) > 2 else ""
        headers = self._parse_headers(lines[1:])

        resp = HttpResponse(
            version=version,
            status_code=status_code,
            reason=reason,
            headers=headers,
        )

        remaining = bytes(self._buffer[header_end:])
        self._buffer.clear()

        body, leftover = self._read_body(remaining, resp.content_length, resp.is_chunked)
        resp.body = body
        self._buffer.extend(leftover)

        return resp

    # ── Internal Helpers ──

    def _find_header_end(self) -> Optional[int]:
        """Find the end of headers (double CRLF). Returns byte offset past the delimiter."""
        marker = b"\r\n\r\n"
        idx = self._buffer.find(marker)
        if idx == -1:
            return None
        return idx + len(marker)

    def _parse_headers(self, lines: List[str]) -> Dict[str, str]:
        """Parse header lines into a lowercase-keyed dict."""
        headers: Dict[str, str] = {}
        count = 0

        for line in lines:
            if not line:
                continue
            if count >= self.MAX_HEADERS:
                raise ParseError(f"Too many headers (max {self.MAX_HEADERS})")

            colon_idx = line.find(":")
            if colon_idx == -1:
                continue  # skip malformed header lines

            key = line[:colon_idx].strip().lower()
            value = line[colon_idx + 1:].strip()

            # Support multi-value headers by comma-joining
            if key in headers:
                headers[key] = headers[key] + ", " + value
            else:
                headers[key] = value
            count += 1

        return headers

    def _read_body(
        self,
        data: bytes,
        content_length: Optional[int],
        chunked: bool,
    ) -> Tuple[bytes, bytes]:
        """
        Extract the body from `data` based on Content-Length or chunked encoding.
        Returns (body, leftover_bytes).
        """
        if chunked:
            return self._decode_chunked(data)

        if content_length is not None and content_length > 0:
            if len(data) >= content_length:
                return data[:content_length], data[content_length:]
            # Not enough data yet — return what we have
            return data, b""

        # No Content-Length, no chunked — no body
        return b"", data

    @staticmethod
    def _decode_chunked(data: bytes) -> Tuple[bytes, bytes]:
        """
        Decode chunked transfer-encoding.
        Returns (decoded_body, leftover_bytes).
        """
        body = bytearray()
        pos = 0

        while pos < len(data):
            # Find chunk size line
            crlf = data.find(b"\r\n", pos)
            if crlf == -1:
                break

            size_str = data[pos:crlf].decode("ascii", errors="replace").strip()
            # Chunk extensions (after ;) are ignored
            if ";" in size_str:
                size_str = size_str.split(";")[0]

            try:
                chunk_size = int(size_str, 16)
            except ValueError:
                break

            if chunk_size == 0:
                # Terminal chunk — skip trailing CRLF
                pos = crlf + 2
                trailing_crlf = data.find(b"\r\n", pos)
                if trailing_crlf != -1:
                    pos = trailing_crlf + 2
                break

            chunk_start = crlf + 2
            chunk_end = chunk_start + chunk_size

            if chunk_end + 2 > len(data):
                break  # incomplete chunk

            body.extend(data[chunk_start:chunk_end])
            pos = chunk_end + 2  # skip trailing CRLF

        return bytes(body), data[pos:]


# ── Pre-built HTTP Error Responses ──

def build_response(status_code: int, reason: str, body: str = "") -> bytes:
    """Build a raw HTTP response ready to send over the wire."""
    body_bytes = body.encode("utf-8") if body else b""
    lines = [
        f"HTTP/1.1 {status_code} {reason}",
        f"Content-Length: {len(body_bytes)}",
        "Content-Type: text/plain; charset=utf-8",
        "Connection: close",
        "",
        "",
    ]
    return "\r\n".join(lines).encode("utf-8") + body_bytes


# Common error responses
RESPONSE_400 = build_response(400, "Bad Request", "400 Bad Request\n")
RESPONSE_403 = build_response(403, "Forbidden", "403 Forbidden — Blocked by NetGuardian IPS\n")
RESPONSE_407 = build_response(407, "Proxy Authentication Required", "407 Authentication Required\n")
RESPONSE_429 = build_response(429, "Too Many Requests", "429 Rate Limit Exceeded\n")
RESPONSE_502 = build_response(502, "Bad Gateway", "502 Bad Gateway — Upstream unreachable\n")
RESPONSE_504 = build_response(504, "Gateway Timeout", "504 Gateway Timeout\n")
CONNECT_200 = b"HTTP/1.1 200 Connection Established\r\n\r\n"
