"""Tests for structured logging configuration."""

from __future__ import annotations

import json
import logging
import sys
from typing import Generator

import pytest

from acme_api.logging import (
    JSONFormatter,
    get_request_id,
)
from acme_api.logging import request_id as _request_id_ctxvar
from acme_api.logging import (
    setup_logging,
)


class TestJSONFormatter:
    def test_formats_basic_record(self) -> None:
        fmt = JSONFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=1,
            msg="hello world", args=(), exc_info=None,
        )
        output = fmt.format(record)
        data = json.loads(output)
        assert data["message"] == "hello world"
        assert data["level"] == "INFO"
        assert data["logger"] == "test"

    def test_includes_request_id(self) -> None:
        token = _request_id_ctxvar.set("abc-123")
        try:
            fmt = JSONFormatter()
            record = logging.LogRecord(
                name="test", level=logging.INFO, pathname="", lineno=1,
                msg="hello", args=(), exc_info=None,
            )
            data = json.loads(fmt.format(record))
            assert data["request_id"] == "abc-123"
        finally:
            _request_id_ctxvar.reset(token)

    def test_null_request_id_when_unset(self) -> None:
        token = _request_id_ctxvar.set(None)
        try:
            fmt = JSONFormatter()
            record = logging.LogRecord(
                name="test", level=logging.INFO, pathname="", lineno=1,
                msg="hello", args=(), exc_info=None,
            )
            data = json.loads(fmt.format(record))
            assert data["request_id"] is None
        finally:
            _request_id_ctxvar.reset(token)

    def test_includes_extra_data(self) -> None:
        fmt = JSONFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=1,
            msg="hello", args=(), exc_info=None,
        )
        record.extra = {"user": "admin", "action": "login"}  # noqa: B027
        data = json.loads(fmt.format(record))
        assert data["user"] == "admin"
        assert data["action"] == "login"

    def test_includes_standard_logging_extra_fields(self) -> None:
        fmt = JSONFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=1,
            msg="hello", args=(), exc_info=None,
        )
        record.cert_id = "cert-123"

        data = json.loads(fmt.format(record))

        assert data["cert_id"] == "cert-123"

    def test_includes_exception_info(self) -> None:
        fmt = JSONFormatter()
        exc = ValueError("oops")
        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname="", lineno=1,
            msg="error happened", args=(),
            exc_info=(exc.__class__, exc, None),
        )

        data = json.loads(fmt.format(record))
        assert "exception" in data
        assert "ValueError: oops" in data["exception"]


class TestSetupLogging:
    @pytest.fixture(autouse=True)
    def _reset_root_logger(self) -> Generator[None]:
        """Reset the root logger's handlers after each test."""
        yield
        logger = logging.getLogger()
        for h in logger.handlers[:]:
            logger.removeHandler(h)

    def test_json_format_sets_json_formatter(self) -> None:
        setup_logging(level="INFO", format_type="json")
        logger = logging.getLogger()
        assert len(logger.handlers) == 1
        handler = logger.handlers[0]
        assert isinstance(handler.formatter, JSONFormatter)

    def test_text_format_sets_standard_formatter(self) -> None:
        setup_logging(level="DEBUG", format_type="text")
        logger = logging.getLogger()
        assert len(logger.handlers) == 1
        handler = logger.handlers[0]
        assert not isinstance(handler.formatter, JSONFormatter)

    def test_sets_log_level_correctly(self) -> None:
        setup_logging(level="DEBUG", format_type="text")
        logger = logging.getLogger()
        assert logger.level == logging.DEBUG

    def test_clears_existing_handlers(self) -> None:
        logger = logging.getLogger()
        dummy = logging.StreamHandler(sys.stdout)
        logger.addHandler(dummy)
        setup_logging(level="INFO", format_type="json")
        assert dummy not in logger.handlers


class TestGetRequestId:
    @pytest.fixture(autouse=True)
    def _reset_ctxvar(self) -> Generator[None]:
        token = _request_id_ctxvar.set(None)
        yield
        try:
            _request_id_ctxvar.reset(token)
        except ValueError:
            pass

    def test_generates_new_id_when_unset(self) -> None:
        rid1 = get_request_id()
        assert isinstance(rid1, str) and len(rid1) > 0

    def test_returns_existing_id_when_set(self) -> None:
        token = _request_id_ctxvar.set("existing-id")
        try:
            rid = get_request_id()
            assert rid == "existing-id"
        finally:
            _request_id_ctxvar.reset(token)

    def test_different_calls_return_same_id_within_context(self) -> None:
        token = _request_id_ctxvar.set("contextual-id")
        try:
            rid1 = get_request_id()
            rid2 = get_request_id()
            assert rid1 == rid2 == "contextual-id"
        finally:
            _request_id_ctxvar.reset(token)
