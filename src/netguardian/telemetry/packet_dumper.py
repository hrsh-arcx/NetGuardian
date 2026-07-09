"""
netguardian.telemetry.packet_dumper — Raw Packet Hex-Dump Utility

Produces Wireshark-style hex dumps of TCP data flowing through the proxy.
Useful for debugging protocol issues or verifying that the IDS engine
is seeing the right bytes. Output goes to a logger or a file.
"""

from __future__ import annotations

import os
from typing import Optional

from netguardian.telemetry.logger import get_logger


class PacketDumper:
    """Formats and logs raw byte data as hex + ASCII dumps."""

    def __init__(
        self,
        enabled: bool = True,
        max_dump_bytes: int = 512,
        dump_dir: Optional[str] = None,
    ):
        self._enabled = enabled
        self._max_dump_bytes = max_dump_bytes
        self._dump_dir = dump_dir
        self._log = get_logger("netguardian.packet_dumper")

        if dump_dir:
            os.makedirs(dump_dir, exist_ok=True)

    def dump(
        self,
        data: bytes,
        label: str = "PACKET",
        conn_id: Optional[str] = None,
        direction: str = ">>>",
    ) -> Optional[str]:
        """
        Create a hex dump of `data` and log it.
        Returns the formatted string, or None if disabled.
        """
        if not self._enabled or not data:
            return None

        truncated = data[: self._max_dump_bytes]
        output = self._format_hexdump(truncated, label, direction, len(data))

        self._log.debug(
            f"[{label}] {direction} {len(data)} bytes (showing {len(truncated)})",
            extra={"conn_id": conn_id},
        )

        if self._dump_dir and conn_id:
            path = os.path.join(self._dump_dir, f"{conn_id}.dump")
            with open(path, "a", encoding="utf-8") as f:
                f.write(output + "\n")

        return output

    @staticmethod
    def _format_hexdump(
        data: bytes,
        label: str,
        direction: str,
        total_len: int,
    ) -> str:
        """
        Format bytes into a Wireshark-style hex dump:
          0000  48 54 54 50 2f 31 2e 31  20 32 30 30 20 4f 4b 0d  |HTTP/1.1 200 OK.|
        """
        lines = [f"── {label} {direction} ({total_len} bytes) ──"]
        width = 16  # bytes per row

        for offset in range(0, len(data), width):
            chunk = data[offset: offset + width]

            # Hex portion
            hex_parts = []
            for i, byte in enumerate(chunk):
                hex_parts.append(f"{byte:02x}")
                if i == 7:
                    hex_parts.append("")  # extra space at midpoint
            hex_str = " ".join(hex_parts).ljust(49)

            # ASCII portion — replace non-printable chars with '.'
            ascii_str = "".join(
                chr(b) if 32 <= b < 127 else "." for b in chunk
            )

            lines.append(f"  {offset:04x}  {hex_str} |{ascii_str}|")

        if len(data) < total_len:
            lines.append(f"  ... ({total_len - len(data)} bytes truncated)")

        return "\n".join(lines)
