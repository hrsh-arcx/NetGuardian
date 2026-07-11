"""Tests for netguardian.inspection.matchers.sql_injection"""

import pytest
from netguardian.inspection.matchers.sql_injection import SqlInjectionMatcher
from netguardian.protocol.http_parser import HttpRequest


class TestSqlInjectionDetection:

    def setup_method(self):
        self.matcher = SqlInjectionMatcher()

    def test_union_select(self):
        req = HttpRequest(uri="/search?q=1 UNION SELECT * FROM users", headers={"host": "x"})
        results = self.matcher.scan(req)
        ids = [r.signature_id for r in results]
        assert any("UNION_SELECT" in i for i in ids)

    def test_or_bypass(self):
        req = HttpRequest(uri="/login?user=admin' OR 1=1--", headers={"host": "x"})
        results = self.matcher.scan(req)
        assert len(results) >= 1

    def test_drop_table(self):
        req = HttpRequest(uri="/; DROP TABLE users", headers={"host": "x"})
        results = self.matcher.scan(req)
        ids = [r.signature_id for r in results]
        assert any("DROP_ALTER" in i for i in ids)

    def test_stacked_query(self):
        req = HttpRequest(uri="/page?id=1; SELECT * FROM passwords", headers={"host": "x"})
        results = self.matcher.scan(req)
        assert len(results) >= 1

    def test_url_encoded_attack(self):
        # %27 = ', %20 = space, %3D = =
        req = HttpRequest(uri="/q=%27%20OR%201%3D1--", headers={"host": "x"})
        results = self.matcher.scan(req)
        assert len(results) >= 1  # URL-decoded before scanning

    def test_body_injection(self):
        req = HttpRequest(
            uri="/api", headers={"host": "x"},
            body=b"field=value' UNION SELECT password FROM admin--",
        )
        results = self.matcher.scan(req)
        assert len(results) >= 1
        assert any(r.location == "body" for r in results)

    def test_sleep_attack(self):
        req = HttpRequest(uri="/id=1 AND SLEEP(5)", headers={"host": "x"})
        results = self.matcher.scan(req)
        ids = [r.signature_id for r in results]
        assert any("SLEEP_BENCHMARK" in i for i in ids)

    def test_clean_request_no_match(self):
        req = HttpRequest(uri="/about?page=contact", headers={"host": "x"})
        results = self.matcher.scan(req)
        assert len(results) == 0
