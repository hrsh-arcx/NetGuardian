"""
netguardian.security.ip_filter — IP Allowlist / Blocklist Engine

Evaluates client IP addresses against ordered ACL rules supporting
individual IPs, CIDR ranges, and a configurable default policy.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Union

from netguardian.telemetry.logger import get_logger

_log = get_logger("netguardian.security.ip_filter")

IpNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
IpAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


class FilterAction(Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass
class FilterResult:
    """Result of an IP filter evaluation."""
    action: FilterAction
    matched_rule: Optional[str] = None  # e.g. "blocklist: 10.0.0.0/8"
    is_default: bool = False            # True if no rule matched


class IPFilter:
    """
    IP-based access control with allowlist/blocklist.

    Evaluation order:
      1. Check blocklist first — explicit blocks take priority
      2. Check allowlist
      3. Fall through to default policy
    """

    def __init__(
        self,
        allowlist: Optional[List[str]] = None,
        blocklist: Optional[List[str]] = None,
        default_policy: str = "allow",
    ):
        self._default_action = FilterAction(default_policy.lower())
        self._allowlist = self._parse_rules(allowlist or [])
        self._blocklist = self._parse_rules(blocklist or [])
        _log.info(
            f"IP filter initialized: {len(self._allowlist)} allow rules, "
            f"{len(self._blocklist)} block rules, default={default_policy}"
        )

    @staticmethod
    def _parse_rules(rules: List[str]) -> List[IpNetwork]:
        """Parse IP strings into network objects. Single IPs become /32 or /128."""
        parsed = []
        for rule in rules:
            try:
                net = ipaddress.ip_network(rule.strip(), strict=False)
                parsed.append(net)
            except ValueError:
                _log.warning(f"Invalid IP rule skipped: {rule!r}")
        return parsed

    def check(self, client_ip: str) -> FilterResult:
        """Evaluate a client IP against the filter rules."""
        try:
            addr = ipaddress.ip_address(client_ip.strip())
        except ValueError:
            _log.warning(f"Unparseable client IP, denying: {client_ip!r}")
            return FilterResult(action=FilterAction.DENY, matched_rule=f"invalid: {client_ip}")

        # Blocklist takes priority
        for net in self._blocklist:
            if addr in net:
                return FilterResult(
                    action=FilterAction.DENY,
                    matched_rule=f"blocklist: {net}",
                )

        # Then allowlist
        for net in self._allowlist:
            if addr in net:
                return FilterResult(
                    action=FilterAction.ALLOW,
                    matched_rule=f"allowlist: {net}",
                )

        # Default policy
        return FilterResult(action=self._default_action, is_default=True)

    def add_to_blocklist(self, ip_or_cidr: str) -> None:
        """Dynamically add an IP/CIDR to the blocklist."""
        try:
            net = ipaddress.ip_network(ip_or_cidr.strip(), strict=False)
            self._blocklist.append(net)
        except ValueError:
            _log.warning(f"Failed to add to blocklist: {ip_or_cidr!r}")

    def add_to_allowlist(self, ip_or_cidr: str) -> None:
        """Dynamically add an IP/CIDR to the allowlist."""
        try:
            net = ipaddress.ip_network(ip_or_cidr.strip(), strict=False)
            self._allowlist.append(net)
        except ValueError:
            _log.warning(f"Failed to add to allowlist: {ip_or_cidr!r}")

    def stats(self) -> dict:
        return {
            "allowlist_rules": len(self._allowlist),
            "blocklist_rules": len(self._blocklist),
            "default_policy": self._default_action.value,
        }
