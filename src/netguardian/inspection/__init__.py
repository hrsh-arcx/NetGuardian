"""
netguardian.inspection — Traffic Inspection Engine (IDS/IPS)

Signature-based intrusion detection and prevention. Scans HTTP
requests against a YAML signature database using pluggable matchers.
"""

from netguardian.inspection.engine import InspectionEngine
from netguardian.inspection.signature_store import SignatureStore, Signature
from netguardian.inspection.actions import InspectionAction, AlertRecord

__all__ = [
    "InspectionEngine",
    "SignatureStore",
    "Signature",
    "InspectionAction",
    "AlertRecord",
]
