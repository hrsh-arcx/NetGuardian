"""
netguardian.core.tunnel — Bidirectional Async Data Relay

Pipes data between two asyncio stream pairs (client ↔ upstream server).
Implements flow control: if one side is slow, we pause reading from the
other to prevent unbounded memory growth.
"""

from __future__ import annotations

import asyncio
from typing import Optional

from netguardian.telemetry.logger import get_logger
from netguardian.telemetry.metrics import MetricsCollector

_log = get_logger("netguardian.core.tunnel")


async def relay(
    reader_a: asyncio.StreamReader,
    writer_a: asyncio.StreamWriter,
    reader_b: asyncio.StreamReader,
    writer_b: asyncio.StreamWriter,
    conn_id: str = "",
    metrics: Optional[MetricsCollector] = None,
    buffer_size: int = 65536,
) -> None:
    """
    Relay data bidirectionally between (a) and (b) until either side closes.

    Typically:
      a = client connection
      b = upstream server connection
    """
    async def _pipe(
        src: asyncio.StreamReader,
        dst: asyncio.StreamWriter,
        direction: str,
    ) -> None:
        try:
            while True:
                data = await src.read(buffer_size)
                if not data:
                    break
                dst.write(data)
                await dst.drain()

                if metrics:
                    await metrics.increment("bytes_transferred", len(data))
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass
        except asyncio.CancelledError:
            raise
        except Exception as e:
            _log.debug(f"[{conn_id}] Tunnel {direction} error: {e}")
        finally:
            try:
                if dst.can_write_eof():
                    dst.write_eof()
            except Exception:
                pass

    # Run both directions concurrently; when either finishes, cancel the other
    task_a_to_b = asyncio.create_task(_pipe(reader_a, writer_b, "client→server"))
    task_b_to_a = asyncio.create_task(_pipe(reader_b, writer_a, "server→client"))

    try:
        done, pending = await asyncio.wait(
            [task_a_to_b, task_b_to_a],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
    finally:
        for writer in (writer_a, writer_b):
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
