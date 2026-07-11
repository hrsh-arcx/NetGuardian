"""
netguardian.inspection.actions — Alert / Block Response Actions

Defines the action types and alert records that the inspection engine
produces when a signature matches.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class InspectionAction(Enum):
    ALLOW = "allow"
    ALERT = "alert"
    BLOCK = "block"


@dataclass
class AlertRecord:
    """Record of a detected threat, emitted by the inspection engine."""
    timestamp: str
    source_ip: str
    target_host: str
    signature_id: str
    signature_name: str
    category: str
    severity: str
    action: InspectionAction
    matched_text: str
    location: str
    request_uri: str

    @staticmethod
    def create(
        source_ip: str,
        target_host: str,
        signature_id: str,
        signature_name: str,
        category: str,
        severity: str,
        action: InspectionAction,
        matched_text: str,
        location: str,
        request_uri: str,
    ) -> "AlertRecord":
        return AlertRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_ip=source_ip,
            target_host=target_host,
            signature_id=signature_id,
            signature_name=signature_name,
            category=category,
            severity=severity,
            action=action,
            matched_text=matched_text,
            location=location,
            request_uri=request_uri,
        )

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "target_host": self.target_host,
            "signature_id": self.signature_id,
            "signature_name": self.signature_name,
            "category": self.category,
            "severity": self.severity,
            "action": self.action.value,
            "matched_text": self.matched_text,
            "location": self.location,
            "request_uri": self.request_uri,
        }
