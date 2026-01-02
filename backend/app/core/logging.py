"""Structured logging with request correlation.

Provides production-grade logging with:
- JSON structured output for log aggregation
- Request correlation IDs (X-Request-ID / X-Correlation-ID)
- Automatic context propagation
- Sensitive data masking
- Performance timing

Usage:
    from app.core.logging import get_logger, request_context

    logger = get_logger(__name__)

    async with request_context(request_id="abc-123"):
        logger.info("Processing request", user_id=user.id)
"""

import json
import logging
import sys
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.config import get_settings

settings = get_settings()

# Context variables for request-scoped data
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
correlation_id_var: ContextVar[str | None] = ContextVar("correlation_id", default=None)
user_id_var: ContextVar[str | None] = ContextVar("user_id", default=None)
identity_id_var: ContextVar[str | None] = ContextVar("identity_id", default=None)

# Sensitive fields to mask in logs
SENSITIVE_FIELDS = {
    "password", "secret", "token", "key", "credential", "authorization",
    "api_key", "apikey", "access_token", "refresh_token", "session",
    "cookie", "master_key", "private_key", "secret_key",
}


def mask_sensitive(data: dict[str, Any]) -> dict[str, Any]:
    """Mask sensitive values in a dictionary."""
    masked = {}
    for key, value in data.items():
        key_lower = key.lower()
        if any(s in key_lower for s in SENSITIVE_FIELDS):
            if isinstance(value, str) and len(value) > 8:
                masked[key] = f"{value[:4]}...{value[-4:]}"
            else:
                masked[key] = "[REDACTED]"
        elif isinstance(value, dict):
            masked[key] = mask_sensitive(value)
        else:
            masked[key] = value
    return masked


@dataclass
class LogContext:
    """Context for structured logging."""
    request_id: str | None = None
    correlation_id: str | None = None
    user_id: str | None = None
    identity_id: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class StructuredFormatter(logging.Formatter):
    """JSON structured log formatter."""

    def format(self, record: logging.LogRecord) -> str:
        # Base log entry
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add request context
        if request_id := request_id_var.get():
            log_entry["request_id"] = request_id
        if correlation_id := correlation_id_var.get():
            log_entry["correlation_id"] = correlation_id
        if user_id := user_id_var.get():
            log_entry["user_id"] = user_id
        if identity_id := identity_id_var.get():
            log_entry["identity_id"] = identity_id

        # Add extra fields from record
        if hasattr(record, "extra_fields"):
            log_entry.update(mask_sensitive(record.extra_fields))

        # Add exception info
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Add source location for errors
        if record.levelno >= logging.WARNING:
            log_entry["source"] = {
                "file": record.pathname,
                "line": record.lineno,
                "function": record.funcName,
            }

        return json.dumps(log_entry)


class HumanFormatter(logging.Formatter):
    """Human-readable log formatter for development."""

    COLORS = {
        "DEBUG": "\033[36m",    # Cyan
        "INFO": "\033[32m",     # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",    # Red
        "CRITICAL": "\033[35m", # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")

        # Build prefix with context
        prefix_parts = []
        if request_id := request_id_var.get():
            prefix_parts.append(f"req={request_id[:8]}")
        if user_id := user_id_var.get():
            prefix_parts.append(f"user={user_id[:8]}")

        prefix = f"[{' '.join(prefix_parts)}] " if prefix_parts else ""

        # Format extra fields
        extra_str = ""
        if hasattr(record, "extra_fields") and record.extra_fields:
            masked = mask_sensitive(record.extra_fields)
            extra_str = " | " + " ".join(f"{k}={v}" for k, v in masked.items())

        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        level = record.levelname[:4]

        message = (
            f"{color}{timestamp} {level}{self.RESET} "
            f"[{record.name}] {prefix}{record.getMessage()}{extra_str}"
        )

        if record.exc_info:
            message += "\n" + self.formatException(record.exc_info)

        return message


class StructuredLogger(logging.Logger):
    """Logger with structured logging support."""

    def _log_with_extra(
        self,
        level: int,
        msg: str,
        args: tuple,
        exc_info: Any = None,
        **kwargs,
    ):
        """Log with extra structured fields."""
        # Create a new record with extra fields
        extra = {"extra_fields": kwargs} if kwargs else {}
        super()._log(level, msg, args, exc_info=exc_info, extra=extra)

    def debug(self, msg: str, *args, **kwargs):
        if self.isEnabledFor(logging.DEBUG):
            self._log_with_extra(logging.DEBUG, msg, args, **kwargs)

    def info(self, msg: str, *args, **kwargs):
        if self.isEnabledFor(logging.INFO):
            self._log_with_extra(logging.INFO, msg, args, **kwargs)

    def warning(self, msg: str, *args, **kwargs):
        if self.isEnabledFor(logging.WARNING):
            self._log_with_extra(logging.WARNING, msg, args, **kwargs)

    def error(self, msg: str, *args, exc_info: Any = None, **kwargs):
        if self.isEnabledFor(logging.ERROR):
            self._log_with_extra(logging.ERROR, msg, args, exc_info=exc_info, **kwargs)

    def critical(self, msg: str, *args, exc_info: Any = None, **kwargs):
        if self.isEnabledFor(logging.CRITICAL):
            self._log_with_extra(logging.CRITICAL, msg, args, exc_info=exc_info, **kwargs)


def get_logger(name: str) -> StructuredLogger:
    """Get a structured logger for a module."""
    logging.setLoggerClass(StructuredLogger)
    logger = logging.getLogger(name)
    logging.setLoggerClass(logging.Logger)
    return logger


def setup_logging(json_output: bool = False, level: str = "INFO"):
    """Configure application logging.

    Args:
        json_output: Use JSON format (for production)
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create handler
    handler = logging.StreamHandler(sys.stdout)

    if json_output:
        handler.setFormatter(StructuredFormatter())
    else:
        handler.setFormatter(HumanFormatter())

    root_logger.addHandler(handler)

    # Reduce noise from libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for request logging and correlation ID propagation."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate or extract request ID
        request_id = (
            request.headers.get("X-Request-ID")
            or request.headers.get("X-Correlation-ID")
            or str(uuid.uuid4())
        )

        # Extract correlation ID (for distributed tracing)
        correlation_id = request.headers.get("X-Correlation-ID") or request_id

        # Set context variables
        request_id_token = request_id_var.set(request_id)
        correlation_id_token = correlation_id_var.set(correlation_id)

        start_time = time.monotonic()
        logger = get_logger("http")

        try:
            # Log request
            logger.info(
                "Request started",
                method=request.method,
                path=request.url.path,
                query=str(request.query_params) if request.query_params else None,
                client_ip=request.client.host if request.client else None,
            )

            response = await call_next(request)

            # Calculate duration
            duration_ms = (time.monotonic() - start_time) * 1000

            # Log response
            logger.info(
                "Request completed",
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration_ms=round(duration_ms, 2),
            )

            # Add correlation headers to response
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Correlation-ID"] = correlation_id

            return response

        except Exception as e:
            duration_ms = (time.monotonic() - start_time) * 1000
            logger.error(
                "Request failed",
                method=request.method,
                path=request.url.path,
                error=str(e),
                duration_ms=round(duration_ms, 2),
                exc_info=True,
            )
            raise

        finally:
            # Reset context variables
            request_id_var.reset(request_id_token)
            correlation_id_var.reset(correlation_id_token)


def set_user_context(user_id: str | None = None, identity_id: str | None = None):
    """Set user context for logging."""
    if user_id:
        user_id_var.set(user_id)
    if identity_id:
        identity_id_var.set(identity_id)


def log_operation(operation: str):
    """Decorator to log function execution with timing."""
    def decorator(func: Callable):
        logger = get_logger(func.__module__)

        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start = time.monotonic()
            try:
                result = await func(*args, **kwargs)
                duration_ms = (time.monotonic() - start) * 1000
                logger.info(
                    f"{operation} completed",
                    operation=operation,
                    duration_ms=round(duration_ms, 2),
                )
                return result
            except Exception as e:
                duration_ms = (time.monotonic() - start) * 1000
                logger.error(
                    f"{operation} failed",
                    operation=operation,
                    error=str(e),
                    duration_ms=round(duration_ms, 2),
                )
                raise

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start = time.monotonic()
            try:
                result = func(*args, **kwargs)
                duration_ms = (time.monotonic() - start) * 1000
                logger.info(
                    f"{operation} completed",
                    operation=operation,
                    duration_ms=round(duration_ms, 2),
                )
                return result
            except Exception as e:
                duration_ms = (time.monotonic() - start) * 1000
                logger.error(
                    f"{operation} failed",
                    operation=operation,
                    error=str(e),
                    duration_ms=round(duration_ms, 2),
                )
                raise

        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator
