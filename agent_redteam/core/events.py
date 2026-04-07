from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_redteam.core.models import Event


class EventBus:
    """In-process event pub/sub for telemetry distribution.

    Phase 1 operates in batch mode: events are buffered in AgentTrace and
    detectors run post-execution.
    """

    def __init__(self) -> None:
        self._subscribers: list[Callable[[Event], Awaitable[None]]] = []
        self._buffer: list[Event] = []

    def subscribe(self, handler: Callable[[Event], Awaitable[None]]) -> None:
        self._subscribers.append(handler)

    async def emit(self, event: Event) -> None:
        self._buffer.append(event)
        for subscriber in self._subscribers:
            await subscriber(event)

    def drain(self) -> list[Event]:
        """Return and clear the buffer."""
        events = list(self._buffer)
        self._buffer.clear()
        return events

    def clear(self) -> None:
        self._buffer.clear()
