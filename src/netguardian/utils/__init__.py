"""
netguardian.utils — Shared Utilities

Foundational modules used across all NetGuardian subsystems:
    - config: YAML configuration loading and validation
    - buffer_pool: Reusable byte buffer pool for zero-copy I/O
    - graceful_shutdown: Signal handling and clean termination
"""

from netguardian.utils.config import ProxyConfig, load_config
from netguardian.utils.buffer_pool import BufferPool
from netguardian.utils.graceful_shutdown import GracefulShutdown

__all__ = [
    "ProxyConfig",
    "load_config",
    "BufferPool",
    "GracefulShutdown",
]
