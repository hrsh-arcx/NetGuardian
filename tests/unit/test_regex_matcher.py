"""Tests for netguardian.inspection.matchers.regex_matcher"""

import re
import pytest
from netguardian.inspection.matchers.regex_matcher import RegexMatcher
from netguardian.inspection.signature_store import Signature
from netguardian.protocol.http_parser import HttpRequest


def _sig(sig_id, pattern, target="uri"):
    return Signature(
        id=sig_id, name=f"Test {sig_id}", category="test",
        severity="high", action="block", target=target,
        pattern=pattern, compiled=re.compile(pattern),
    )


class TestRegexMatcher:

    def test_uri_match(self):
        matcher = RegexMatcher([_sig("T-001", r"(?i)union\s+select")])
        req = HttpRequest(uri="/search?q=1 UNION SELECT *", headers={"host": "x.com"})
        results = matcher.scan(req)
        assert len(results) == 1
        assert results[0].signature_id == "T-001"
        assert results[0].location == "uri"

    def test_no_match(self):
        matcher = RegexMatcher([_sig("T-002", r"DROP TABLE")])
        req = HttpRequest(uri="/safe/path", headers={"host": "x.com"})
        assert matcher.scan(req) == []

    def test_header_target(self):
        matcher = RegexMatcher([_sig("T-003", r"(?i)sqlmap", target="headers")])
        req = HttpRequest(
            uri="/", headers={"host": "x.com", "user-agent": "sqlmap/1.0"}
        )
        results = matcher.scan(req)
        assert len(results) == 1
        assert results[0].location == "headers"

    def test_body_target(self):
        matcher = RegexMatcher([_sig("T-004", r"password=admin", target="body")])
        req = HttpRequest(
            uri="/login", headers={"host": "x.com"},
            body=b"username=root&password=admin",
        )
        results = matcher.scan(req)
        assert len(results) == 1
        assert results[0].location == "body"

    def test_any_target_scans_all(self):
        matcher = RegexMatcher([_sig("T-005", r"evil", target="any")])
        req = HttpRequest(
            uri="/evil", headers={"host": "x.com", "x-custom": "evil"},
            body=b"evil payload",
        )
        results = matcher.scan(req)
        assert len(results) == 3  # found in uri, headers, and body

    def test_url_decoded_match(self):
        matcher = RegexMatcher([_sig("T-006", r"OR 1=1")])
        req = HttpRequest(uri="/search?q=1%27%20OR%201%3D1", headers={"host": "x.com"})
        results = matcher.scan(req)
        assert len(results) == 1

    def test_multiple_signatures(self):
        matcher = RegexMatcher([
            _sig("T-007", r"(?i)select"),
            _sig("T-008", r"(?i)union"),
        ])
        req = HttpRequest(uri="/q=UNION SELECT 1", headers={"host": "x.com"})
        results = matcher.scan(req)
        assert len(results) == 2
