"""
Tests for netguardian.protocol.http_parser — HTTP/1.1 Parser

Covers: request line parsing, header extraction, CONNECT method,
chunked encoding, Content-Length bodies, malformed input, and
pre-built error responses.
"""

import pytest
from netguardian.protocol.http_parser import (
    HttpParser, HttpRequest, HttpResponse, ParseError,
    build_response, RESPONSE_403, CONNECT_200,
)


def _make_request(raw: str) -> bytes:
    """Helper: convert a multiline string to raw HTTP bytes."""
    return raw.replace("\n", "\r\n").encode("utf-8")


# ── Request Line Parsing ──

class TestRequestLineParsing:

    def test_simple_get(self):
        parser = HttpParser()
        parser.feed(_make_request(
            "GET /index.html HTTP/1.1\n"
            "Host: example.com\n"
            "\n"
        ))
        req = parser.parse_request()
        assert req is not None
        assert req.method == "GET"
        assert req.uri == "/index.html"
        assert req.version == "HTTP/1.1"

    def test_post_with_body(self):
        body = "username=admin&password=test"
        parser = HttpParser()
        parser.feed(_make_request(
            "POST /login HTTP/1.1\n"
            "Host: example.com\n"
            f"Content-Length: {len(body)}\n"
            "\n"
        ) + body.encode())
        req = parser.parse_request()
        assert req.method == "POST"
        assert req.body == body.encode()
        assert req.content_length == len(body)

    def test_connect_method(self):
        parser = HttpParser()
        parser.feed(_make_request(
            "CONNECT example.com:443 HTTP/1.1\n"
            "Host: example.com:443\n"
            "\n"
        ))
        req = parser.parse_request()
        assert req.is_connect is True
        assert req.host == "example.com"
        assert req.port == 443

    def test_missing_version_defaults(self):
        parser = HttpParser()
        parser.feed(_make_request(
            "GET /path\n"
            "Host: test.com\n"
            "\n"
        ))
        req = parser.parse_request()
        assert req.version == "HTTP/1.1"  # default

    def test_unknown_method_raises(self):
        parser = HttpParser()
        parser.feed(_make_request(
            "INVALID /path HTTP/1.1\n"
            "Host: test.com\n"
            "\n"
        ))
        with pytest.raises(ParseError, match="Unknown HTTP method"):
            parser.parse_request()


# ── Header Parsing ──

class TestHeaderParsing:

    def test_case_insensitive_keys(self):
        parser = HttpParser()
        parser.feed(_make_request(
            "GET / HTTP/1.1\n"
            "Host: example.com\n"
            "Content-Type: text/html\n"
            "X-Custom-Header: value123\n"
            "\n"
        ))
        req = parser.parse_request()
        assert req.headers["host"] == "example.com"
        assert req.headers["content-type"] == "text/html"
        assert req.headers["x-custom-header"] == "value123"

    def test_multi_value_headers(self):
        parser = HttpParser()
        parser.feed(_make_request(
            "GET / HTTP/1.1\n"
            "Host: example.com\n"
            "Accept: text/html\n"
            "Accept: application/json\n"
            "\n"
        ))
        req = parser.parse_request()
        assert "text/html" in req.headers["accept"]
        assert "application/json" in req.headers["accept"]

    def test_host_port_extraction(self):
        parser = HttpParser()
        parser.feed(_make_request(
            "GET / HTTP/1.1\n"
            "Host: example.com:8080\n"
            "\n"
        ))
        req = parser.parse_request()
        assert req.host == "example.com"
        assert req.port == 8080

    def test_default_port_80(self):
        parser = HttpParser()
        parser.feed(_make_request(
            "GET / HTTP/1.1\n"
            "Host: example.com\n"
            "\n"
        ))
        req = parser.parse_request()
        assert req.port == 80


# ── Body Handling ──

class TestBodyHandling:

    def test_chunked_transfer(self):
        parser = HttpParser()
        raw = (
            b"GET / HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"5\r\nHello\r\n"
            b"6\r\n World\r\n"
            b"0\r\n\r\n"
        )
        parser.feed(raw)
        req = parser.parse_request()
        assert req.body == b"Hello World"
        assert req.is_chunked is True

    def test_no_body_no_content_length(self):
        parser = HttpParser()
        parser.feed(_make_request(
            "GET / HTTP/1.1\n"
            "Host: example.com\n"
            "\n"
        ))
        req = parser.parse_request()
        assert req.body == b""
        assert req.content_length is None

    def test_incomplete_headers_returns_none(self):
        parser = HttpParser()
        parser.feed(b"GET / HTTP/1.1\r\nHost: exam")
        req = parser.parse_request()
        assert req is None  # needs more data


# ── Response Parsing ──

class TestResponseParsing:

    def test_simple_200(self):
        parser = HttpParser()
        parser.feed(_make_request(
            "HTTP/1.1 200 OK\n"
            "Content-Length: 2\n"
            "\n"
        ) + b"OK")
        resp = parser.parse_response()
        assert resp is not None
        assert resp.status_code == 200
        assert resp.reason == "OK"
        assert resp.body == b"OK"

    def test_404_response(self):
        parser = HttpParser()
        parser.feed(_make_request(
            "HTTP/1.1 404 Not Found\n"
            "Content-Length: 0\n"
            "\n"
        ))
        resp = parser.parse_response()
        assert resp.status_code == 404
        assert resp.reason == "Not Found"


# ── URL Decoding ──

class TestUrlDecoding:

    def test_decoded_uri(self):
        req = HttpRequest(uri="/search?q=1%27%20OR%201%3D1--")
        assert "1' OR 1=1--" in req.decoded_uri

    def test_plain_uri_unchanged(self):
        req = HttpRequest(uri="/about")
        assert req.decoded_uri == "/about"


# ── Malformed Input ──

class TestMalformedInput:

    def test_empty_request_line_raises(self):
        parser = HttpParser()
        parser.feed(b"\r\n\r\n")
        with pytest.raises(ParseError):
            parser.parse_request()

    def test_garbage_data(self):
        parser = HttpParser()
        parser.feed(b"\x00\xff\xfe\r\n\r\n")
        with pytest.raises(ParseError):
            parser.parse_request()

    def test_oversized_headers_raises(self):
        parser = HttpParser()
        # 70KB of header data without double CRLF
        parser.feed(b"GET / HTTP/1.1\r\n" + b"X: " + b"A" * 70000)
        with pytest.raises(ParseError, match="exceed"):
            parser.parse_request()


# ── Pre-built Responses ──

class TestPrebuiltResponses:

    def test_build_response(self):
        resp = build_response(200, "OK", "hello")
        assert b"HTTP/1.1 200 OK" in resp
        assert b"Content-Length: 5" in resp
        assert resp.endswith(b"hello")

    def test_403_response(self):
        assert b"403" in RESPONSE_403
        assert b"Forbidden" in RESPONSE_403

    def test_connect_200(self):
        assert CONNECT_200 == b"HTTP/1.1 200 Connection Established\r\n\r\n"

    def test_parser_clear_resets(self):
        parser = HttpParser()
        parser.feed(b"some data")
        assert parser.buffered > 0
        parser.clear()
        assert parser.buffered == 0
