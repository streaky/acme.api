"""Structured logging configuration for acme.api.

Provides JSON formatting for production logs and standard text for development,
including request ID context propagation via contextvars.
"""

import json
import logging
from contextvars import ContextVar
from typing import Any
from uuid import uuid4

# Thread-safe storage for the current request's correlation ID
request_id: ContextVar[str | None] = ContextVar("request_id", default=None)

_STANDARD_LOG_RECORD_ATTRS = set(logging.makeLogRecord({}).__dict__)


class JSONFormatter(logging.Formatter):
    """A logging formatter that outputs in JSON format."""

    def format(self, record: logging.LogRecord) -> str:
        # Capture context-aware data
        log_data: dict[str, Any] = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "request_id": request_id.get(),
        }

        for key, value in record.__dict__.items():
            if key not in _STANDARD_LOG_RECORD_ATTRS and key != "extra":
                log_data[key] = value

        extra_data: Any = getattr(record, "extra", None)
        if isinstance(extra_data, dict):
            log_data.update(extra_data)

        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data, default=str)


def setup_logging(level: str, format_type: str = "json") -> None:
    """Configures the root logger."""
    handler = logging.StreamHandler()

    if format_type == "json":
        handler.setFormatter(JSONFormatter())
    else:
        formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
        handler.setFormatter(formatter)

    logger = logging.getLogger()
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    # Clear existing handlers to avoid duplication if called twice (e.g. in tests)
    for h in logger.handlers[:]:
        logger.removeHandler(h)
    logger.addHandler(handler)


def get_request_id() -> str:
    """Returns the current request ID or generates a new one."""
    rid = request_id.get()
    if rid is None:
        rid = str(uuid4())
        request_id.set(rid)
    return rid
