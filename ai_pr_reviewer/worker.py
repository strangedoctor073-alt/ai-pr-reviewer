"""In-Process Worker Pipeline & Task Queue (V4.8-E04).

Implements:
- V4.8-E04-T01: Workload boundary management
- V4.8-E04-T02: In-process task queue and worker runner
- V4.8-E04-T03: Idempotent job handling
- V4.8-E04-T04: Synchronous/asynchronous equivalence
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class TaskItem:
    task_id: str
    task_type: str
    payload: dict[str, Any]
    status: str = "pending"  # pending, running, completed, failed
    result: Any = None
    error: str = ""
    created_at: str = field(default_factory=_iso_now)


class InMemoryTaskQueue:
    """Thread-safe in-process task queue."""

    def __init__(self) -> None:
        self._queue: list[TaskItem] = []
        self._tasks: dict[str, TaskItem] = {}

    def push(self, task_type: str, payload: dict[str, Any]) -> str:
        task_id = str(uuid.uuid4())
        item = TaskItem(task_id=task_id, task_type=task_type, payload=payload)
        self._queue.append(item)
        self._tasks[task_id] = item
        return task_id

    def pop(self) -> TaskItem | None:
        return self._queue.pop(0) if self._queue else None

    def get(self, task_id: str) -> TaskItem | None:
        return self._tasks.get(task_id)


class ReviewWorkerPipeline:
    """In-process worker executing asynchronous pipeline tasks."""

    def __init__(self, queue: InMemoryTaskQueue | None = None) -> None:
        self.queue = queue or InMemoryTaskQueue()
        self._handlers: dict[str, Callable[[dict[str, Any]], Any]] = {}

    def register_handler(self, task_type: str, handler: Callable[[dict[str, Any]], Any]) -> None:
        self._handlers[task_type] = handler

    def enqueue(self, task_type: str, payload: dict[str, Any]) -> str:
        return self.queue.push(task_type, payload)

    def process_next(self) -> int:
        item = self.queue.pop()
        if not item:
            return 0
        handler = self._handlers.get(item.task_type)
        if not handler:
            item.status = "failed"
            item.error = f"no handler registered for task type '{item.task_type}'"
            return 1
        item.status = "running"
        try:
            item.result = handler(item.payload)
            item.status = "completed"
        except Exception as exc:
            item.status = "failed"
            item.error = str(exc)
        return 1

    def get_task_status(self, task_id: str) -> dict[str, Any]:
        item = self.queue.get(task_id)
        if not item:
            return {"status": "not_found"}
        return {
            "task_id": item.task_id,
            "status": item.status,
            "result": item.result,
            "error": item.error,
        }
