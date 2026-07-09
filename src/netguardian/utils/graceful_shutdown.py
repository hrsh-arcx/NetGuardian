"""
netguardian.utils.graceful_shutdown — Clean Termination Handler
graceful shutdown sequence -
    1. Stop accepting new connections
    2. Signal all active connections to finish their current request
    3. Wait up to `drain_timeout` seconds for them to complete
    4. Force-close anything still lingering
    5. Flush logs and metrics
"""

from __future__ import annotations

import asyncio
import signal
import sys
from typing import Callable, List, Optional


class GracefulShutdown:

    def __init__(self, drain_timeout: float = 10.0):
        self.drain_timeout = drain_timeout
        self.is_shutting_down = False

        # Event that gets set when shutdown is triggered.
        self._shutdown_event: Optional[asyncio.Event] = None

        # Callbacks to run during shutdown (e.g., flush metrics, close DB).
        self._cleanup_callbacks: List[Callable] = []

        # Track active connection tasks so we can wait for them to drain.
        self._active_tasks: List[asyncio.Task] = []

    def _ensure_event(self) -> asyncio.Event:
        if self._shutdown_event is None:
            self._shutdown_event = asyncio.Event()
        return self._shutdown_event

    def register_signals(self, loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
        
        if loop is None:
            loop = asyncio.get_running_loop()

        if sys.platform == "win32":
            signal.signal(signal.SIGINT, self._sync_signal_handler)
            signal.signal(signal.SIGTERM, self._sync_signal_handler)
        else:
            # Unix/macOS: use the proper asyncio signal API.
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, lambda: self._trigger_shutdown(loop))

    def _sync_signal_handler(self, signum: int, frame) -> None:
        self.is_shutting_down = True
        event = self._ensure_event()
        try:
            loop = asyncio.get_running_loop()
            loop.call_soon_threadsafe(event.set)
        except RuntimeError:
            pass

    def _trigger_shutdown(self, loop: asyncio.AbstractEventLoop) -> None:
        #Async-safe shutdown trigger for Unix signal handlers.
        self.is_shutting_down = True
        self._ensure_event().set()

    def track_task(self, task: asyncio.Task) -> None:
        #Register an active connection task for drain tracking.
        self._active_tasks.append(task)
        # Auto-remove when the task finishes (success or failure)
        task.add_done_callback(self._task_done)

    def _task_done(self, task: asyncio.Task) -> None:
        #Callback: remove a finished task from the active list.
        try:
            self._active_tasks.remove(task)
        except ValueError:
            pass 

    def add_cleanup_callback(self, callback: Callable) -> None:
        #Register a function to call during shutdown cleanup.
        self._cleanup_callbacks.append(callback)

    @property
    def active_connections(self) -> int:
        return len(self._active_tasks)

    async def wait_for_shutdown(self) -> None:
        await self._ensure_event().wait()

    async def drain(self) -> None:
        if self._active_tasks:
            # Give active connections time to finish their current work
            pending = [t for t in self._active_tasks if not t.done()]
            if pending:
                _, still_running = await asyncio.wait(
                    pending,
                    timeout=self.drain_timeout,
                )

                # Force-cancel anything that didn't finish in time
                for task in still_running:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass

        # Run cleanup callbacks (flush logs, export final metrics, etc.)
        for callback in self._cleanup_callbacks:
            try:
                result = callback()
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                pass

    def reset(self) -> None:
        self.is_shutting_down = False
        self._shutdown_event = None
        self._active_tasks.clear()
        self._cleanup_callbacks.clear()
