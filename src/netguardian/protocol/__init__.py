"""
netguardian.protocol — Protocol Parsing

Streaming HTTP/1.1 parser and async DNS resolver with caching.
No third-party dependencies — built on stdlib only.
"""

from netguardian.protocol.http_parser import HttpRequest, HttpResponse, HttpParser
from netguardian.protocol.dns_resolver import DnsResolver

__all__ = [
    "HttpRequest",
    "HttpResponse",
    "HttpParser",
    "DnsResolver",
]
