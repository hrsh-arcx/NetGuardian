"""
Tests for netguardian.security.ip_filter — IP ACL Engine
"""

import pytest
from netguardian.security.ip_filter import IPFilter, FilterAction


class TestSingleIPMatching:

    def test_blocklist_exact_match(self):
        f = IPFilter(blocklist=["192.168.1.100"])
        result = f.check("192.168.1.100")
        assert result.action == FilterAction.DENY

    def test_allowlist_exact_match(self):
        f = IPFilter(allowlist=["10.0.0.5"], default_policy="deny")
        result = f.check("10.0.0.5")
        assert result.action == FilterAction.ALLOW

    def test_no_match_uses_default_allow(self):
        f = IPFilter(default_policy="allow")
        result = f.check("8.8.8.8")
        assert result.action == FilterAction.ALLOW
        assert result.is_default is True

    def test_no_match_uses_default_deny(self):
        f = IPFilter(default_policy="deny")
        result = f.check("8.8.8.8")
        assert result.action == FilterAction.DENY
        assert result.is_default is True

    def test_blocklist_takes_priority(self):
        """If an IP is in both lists, blocklist wins."""
        f = IPFilter(allowlist=["10.0.0.1"], blocklist=["10.0.0.1"])
        result = f.check("10.0.0.1")
        assert result.action == FilterAction.DENY


class TestCIDRMatching:

    def test_cidr_blocklist(self):
        f = IPFilter(blocklist=["10.0.0.0/8"])
        assert f.check("10.1.2.3").action == FilterAction.DENY
        assert f.check("10.255.255.255").action == FilterAction.DENY
        assert f.check("11.0.0.1").action == FilterAction.ALLOW  # outside /8

    def test_cidr_allowlist(self):
        f = IPFilter(allowlist=["192.168.0.0/16"], default_policy="deny")
        assert f.check("192.168.1.1").action == FilterAction.ALLOW
        assert f.check("192.168.100.50").action == FilterAction.ALLOW
        assert f.check("172.16.0.1").action == FilterAction.DENY

    def test_small_subnet(self):
        f = IPFilter(blocklist=["10.0.0.0/30"])
        # /30 covers .0, .1, .2, .3
        assert f.check("10.0.0.0").action == FilterAction.DENY
        assert f.check("10.0.0.3").action == FilterAction.DENY
        assert f.check("10.0.0.4").action == FilterAction.ALLOW


class TestIPv6:

    def test_ipv6_loopback(self):
        f = IPFilter(allowlist=["::1"])
        assert f.check("::1").action == FilterAction.ALLOW

    def test_ipv6_blocklist(self):
        f = IPFilter(blocklist=["fd00::/8"])
        assert f.check("fd12:3456:789a::1").action == FilterAction.DENY


class TestEdgeCases:

    def test_invalid_ip_denied(self):
        f = IPFilter(default_policy="allow")
        result = f.check("not-an-ip")
        assert result.action == FilterAction.DENY

    def test_invalid_rule_skipped(self):
        """Invalid entries in the config should not crash."""
        f = IPFilter(blocklist=["not-valid", "10.0.0.1"])
        assert f.check("10.0.0.1").action == FilterAction.DENY

    def test_empty_lists(self):
        f = IPFilter(allowlist=[], blocklist=[], default_policy="allow")
        result = f.check("1.2.3.4")
        assert result.action == FilterAction.ALLOW
        assert result.is_default is True

    def test_dynamic_add_blocklist(self):
        f = IPFilter()
        assert f.check("5.5.5.5").action == FilterAction.ALLOW
        f.add_to_blocklist("5.5.5.5")
        assert f.check("5.5.5.5").action == FilterAction.DENY

    def test_stats(self):
        f = IPFilter(allowlist=["1.1.1.1"], blocklist=["2.2.2.2", "3.3.3.3"])
        s = f.stats()
        assert s["allowlist_rules"] == 1
        assert s["blocklist_rules"] == 2
