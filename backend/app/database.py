"""Database connection and session management."""

import re
import json
from typing import Any

from sqlalchemy import TypeDecorator, Text, String
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings


class GUID(TypeDecorator):
    """Database-agnostic UUID type.

    Uses CHAR(36) storage which works with both SQLite and PostgreSQL.
    This replaces postgresql.UUID for cross-database compatibility.
    """

    impl = String(36)
    cache_ok = True

    def process_bind_param(self, value, dialect) -> str | None:
        if value is None:
            return None
        return str(value)

    def process_result_value(self, value, dialect) -> str | None:
        if value is None:
            return None
        return str(value)


class StringList(TypeDecorator):
    """Database-agnostic string list type.

    Uses JSON storage which works with both SQLite and PostgreSQL.
    This replaces ARRAY(String) for cross-database compatibility.
    """

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: list[str] | None, dialect) -> str | None:
        if value is None:
            return None
        return json.dumps(value)

    def process_result_value(self, value: str | list | None, dialect) -> list[str] | None:
        if value is None:
            return None
        # PostgreSQL returns already-parsed lists, SQLite returns strings
        if isinstance(value, list):
            return value
        return json.loads(value)


class JSONType(TypeDecorator):
    """Database-agnostic JSON type.

    Uses JSON storage which works with both SQLite and PostgreSQL.
    This replaces JSONB for cross-database compatibility.
    """

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: dict[str, Any] | None, dialect) -> str | None:
        if value is None:
            return None
        return json.dumps(value)

    def process_result_value(self, value: str | dict | list | None, dialect) -> dict[str, Any] | list | None:
        if value is None:
            return None
        # PostgreSQL returns already-parsed objects, SQLite returns strings
        if isinstance(value, (dict, list)):
            return value
        return json.loads(value)


class Base(DeclarativeBase):
    """Base class for all models."""

    pass


# Lazy initialization to support testing with different databases
_engine = None
_async_session_maker = None


# Async drivers each dialect is expected to use. The engine is created with
# create_async_engine, so a sync driver URL fails at startup with an opaque
# SQLAlchemy error rather than anything a reader can act on.
_ASYNC_DRIVERS = {
    "postgresql": "asyncpg",
    "mysql": "aiomysql",
    "sqlite": "aiosqlite",
}


def _redact_dsn(url: str) -> str:
    """Mask credentials in a DSN so it can appear in an error or a log line.

    These messages are raised at startup and land in tracebacks, container
    logs and crash reporters. `postgres://app:hunter2@db/prod` echoed verbatim
    puts the database password in all three.
    """
    if not isinstance(url, str):
        return "<not-a-string>"
    # Match any userinfo segment, not just one following "//". The message
    # that echoes the whole URL is the MALFORMED case, which by definition may
    # not have a well-formed "//" authority: `postgres:/app:pw@db` must redact
    # too. Anchoring on "//" left the password visible in exactly the branch
    # that prints it.
    return re.sub(r"[^/@\s]+@", "***@", url)


def normalize_database_url(url: str) -> str:
    """Normalize a database URL to an async-capable SQLAlchemy URL.

    Every managed Postgres provider (Heroku, Render, Railway, Supabase's
    pooler) hands out ``postgres://``. SQLAlchemy dropped that alias in 1.4, so
    passing it through produced::

        NoSuchModuleError: Can't load plugin: sqlalchemy.dialects:postgres

    which says nothing about what to change. Two rewrites are applied, and
    anything still unusable is rejected with an actionable message:

    1. ``postgres://`` becomes ``postgresql://``.
    2. A dialect with no ``+driver`` gains its async driver.

    Raises:
        ValueError: if the URL names a driver that cannot work with asyncio.
    """
    if not url or "://" not in url:
        raise ValueError(
            f"DATABASE_URL is not a connection string: {_redact_dsn(url)!r}. "
            "Expected something like postgresql+asyncpg://user:pass@host/db"
        )

    scheme, rest = url.split("://", 1)
    scheme = scheme.lower()

    if scheme == "postgres":
        scheme = "postgresql"

    if "+" in scheme:
        dialect, driver = scheme.split("+", 1)
        expected = _ASYNC_DRIVERS.get(dialect)
        if expected and driver != expected:
            raise ValueError(
                f"DATABASE_URL uses the synchronous driver {driver!r}. "
                f"CryptoServe runs on asyncio; use {dialect}+{expected}:// instead."
            )
        return f"{scheme}://{rest}"

    driver = _ASYNC_DRIVERS.get(scheme)
    if driver is None:
        raise ValueError(
            f"Unsupported database dialect {scheme!r}. " f"Supported: {', '.join(sorted(_ASYNC_DRIVERS))}."
        )

    return f"{scheme}+{driver}://{rest}"


def get_engine():
    """Get or create the database engine.

    Connection pooling is configured for horizontal scaling:
    - pool_size: Base number of connections per instance
    - max_overflow: Additional temporary connections under load
    - pool_recycle: Recycle connections to handle cloud DB timeouts
    - pool_pre_ping: Verify connections are alive before use
    """
    global _engine
    if _engine is None:
        settings = get_settings()

        database_url = normalize_database_url(settings.database_url)

        # SQLite doesn't support connection pooling the same way
        is_sqlite = database_url.startswith("sqlite")

        pool_options = {
            "echo": False,
            "pool_pre_ping": True,  # Verify connections before use
        }

        if not is_sqlite:
            # PostgreSQL/MySQL connection pool settings for scaling
            pool_options.update(
                {
                    "pool_size": settings.db_pool_size,  # Base connections per instance
                    "max_overflow": settings.db_max_overflow,  # Extra connections under load
                    "pool_recycle": settings.db_pool_recycle,  # Recycle after N seconds (RDS timeout)
                    "pool_timeout": 30,  # Wait up to 30s for connection
                }
            )

        _engine = create_async_engine(database_url, **pool_options)
    return _engine


def get_session_maker():
    """Get or create the session maker."""
    global _async_session_maker
    if _async_session_maker is None:
        _async_session_maker = async_sessionmaker(
            get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _async_session_maker


async def get_db() -> AsyncSession:
    """Dependency for getting database session."""
    async with get_session_maker()() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    """Initialize database tables."""
    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db():
    """Close database connections."""
    await get_engine().dispose()
