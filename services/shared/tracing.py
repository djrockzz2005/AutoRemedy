from __future__ import annotations

import contextvars
import uuid
from typing import Iterable

TRACE_ID_HEADER = "x-trace-id"
SPAN_ID_HEADER = "x-span-id"
PARENT_SPAN_ID_HEADER = "x-parent-span-id"

_trace_id: contextvars.ContextVar[str] = contextvars.ContextVar("trace_id", default="")
_span_id: contextvars.ContextVar[str] = contextvars.ContextVar("span_id", default="")
_parent_span_id: contextvars.ContextVar[str] = contextvars.ContextVar("parent_span_id", default="")


def new_id() -> str:
    return uuid.uuid4().hex


def set_trace_context(trace_id: str | None = None, span_id: str | None = None, parent_span_id: str | None = None) -> dict[str, str]:
    current_trace = trace_id or _trace_id.get() or new_id()
    current_span = span_id or new_id()
    _trace_id.set(current_trace)
    _span_id.set(current_span)
    _parent_span_id.set(parent_span_id or "")
    return current_trace_context()


def current_trace_context() -> dict[str, str]:
    return {
        TRACE_ID_HEADER: _trace_id.get() or new_id(),
        SPAN_ID_HEADER: _span_id.get() or new_id(),
        PARENT_SPAN_ID_HEADER: _parent_span_id.get(),
    }


def trace_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    headers = current_trace_context()
    if extra:
        headers.update(extra)
    return headers


def child_trace_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    parent = current_trace_context()
    headers = {
        TRACE_ID_HEADER: parent[TRACE_ID_HEADER],
        SPAN_ID_HEADER: new_id(),
        PARENT_SPAN_ID_HEADER: parent[SPAN_ID_HEADER],
    }
    if extra:
        headers.update(extra)
    return headers


def extract_trace_headers(headers: dict | None) -> dict[str, str]:
    headers = headers or {}
    trace_id = headers.get(TRACE_ID_HEADER) or headers.get(TRACE_ID_HEADER.title()) or new_id()
    span_id = headers.get(SPAN_ID_HEADER) or headers.get(SPAN_ID_HEADER.title()) or new_id()
    parent = headers.get(PARENT_SPAN_ID_HEADER) or headers.get(PARENT_SPAN_ID_HEADER.title()) or ""
    return set_trace_context(str(trace_id), str(span_id), str(parent))


def grpc_metadata() -> list[tuple[str, str]]:
    headers = child_trace_headers()
    return list(headers.items())


def extract_grpc_metadata(metadata: Iterable) -> dict[str, str]:
    payload = {}
    for item in metadata:
        key = getattr(item, "key", None)
        value = getattr(item, "value", None)
        if key is None and isinstance(item, tuple) and len(item) == 2:
            key, value = item
        if key:
            payload[str(key).lower()] = str(value)
    return extract_trace_headers(payload)
