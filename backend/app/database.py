"""Database connection and session management."""

import json
from typing import Any

from sqlalchemy import TypeDecorator, Text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings


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


def get_engine():
    """Get or create the database engine."""
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_async_engine(
            settings.database_url,
            echo=False,
            pool_pre_ping=True,
        )
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
