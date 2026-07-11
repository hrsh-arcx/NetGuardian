"""Tests for netguardian.inspection.matchers.header_matcher"""

import pytest
from netguardian.inspection.matchers.header_matcher import HeaderMatcher
from netguardian.protocol.http_parser import HttpRequest


class TestHeaderMatcher:

    def setup_method(self):
        self.matcher = HeaderMatcher()

    def test_missing_host_detected(self):
        req = HttpRequest(method="GET", uri="/", headers={})
        results = self.matcher.scan(req)
        ids = [r.signature_id for r in results]
        assert "NG-HDR-001" in ids

    def test_connect_skips_host_check(self):
        req = HttpRequest(method="CONNECT", uri="example.com:443", headers={})
        results = self.matcher.scan(req)
        ids = [r.signature_id for r in results]
        assert "NG-HDR-001" not in ids  # CONNECT doesn't need Host

    def test_missing_user_agent(self):
        req = HttpRequest(uri="/", headers={"host": "x.com"})
        results = self.matcher.scan(req)
        ids = [r.signature_id for r in results]
        assert "NG-HDR-002" in ids

    def test_crlf_injection(self):
        req = HttpRequest(uri="/", headers={"host": "x.com", "x-bad": "value\r\nEvil: header"})
        results = self.matcher.scan(req)
        ids = [r.signature_id for r in results]
        assert "NG-HDR-003" in ids

    def test_oversized_header(self):
        req = HttpRequest(uri="/", headers={"host": "x.com", "x-big": "A" * 5000})
        results = self.matcher.scan(req)
        ids = [r.signature_id for r in results]
        assert "NG-HDR-004" in ids

    def test_clean_headers_no_match(self):
        req = HttpRequest(
            uri="/", headers={"host": "x.com", "user-agent": "Mozilla/5.0"}
        )
        results = self.matcher.scan(req)
        assert len(results) == 0
