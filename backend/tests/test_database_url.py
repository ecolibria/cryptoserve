"""Database URL normalization.

The engine is created with ``create_async_engine``, so the URL must name an
async driver. Every managed Postgres provider hands out ``postgres://``, which
SQLAlchemy dropped in 1.4; passing it through aborted startup with
``NoSuchModuleError: Can't load plugin: sqlalchemy.dialects:postgres``, which
tells an operator nothing about what to change.
"""

import pytest

from app.database import normalize_database_url


class TestLegacyPostgresScheme:
    def test_postgres_scheme_is_rewritten(self):
        # The exact failure observed at startup before this normalizer existed.
        assert (
            normalize_database_url("postgres://user:pw@db.example.com:5432/cryptoserve")
            == "postgresql+asyncpg://user:pw@db.example.com:5432/cryptoserve"
        )

    def test_postgres_scheme_keeps_query_parameters(self):
        assert (
            normalize_database_url("postgres://u:p@h/db?sslmode=require")
            == "postgresql+asyncpg://u:p@h/db?sslmode=require"
        )

    def test_uppercase_scheme_is_handled(self):
        assert normalize_database_url("POSTGRES://u:p@h/db") == "postgresql+asyncpg://u:p@h/db"


class TestAsyncDriverIsSupplied:
    @pytest.mark.parametrize(
        "given,expected",
        [
            ("postgresql://u:p@h/db", "postgresql+asyncpg://u:p@h/db"),
            ("mysql://u:p@h/db", "mysql+aiomysql://u:p@h/db"),
            ("sqlite:///./cryptoserve.db", "sqlite+aiosqlite:///./cryptoserve.db"),
        ],
    )
    def test_missing_driver_is_filled_in(self, given, expected):
        assert normalize_database_url(given) == expected

    @pytest.mark.parametrize(
        "url",
        [
            "postgresql+asyncpg://u:p@h/db",
            "mysql+aiomysql://u:p@h/db",
            "sqlite+aiosqlite:///./cryptoserve.db",
        ],
    )
    def test_correct_url_is_left_alone(self, url):
        assert normalize_database_url(url) == url

    def test_default_settings_url_is_unchanged(self):
        from app.config import Settings

        default = Settings.model_fields["database_url"].default
        assert normalize_database_url(default) == default


class TestRejections:
    def test_sync_driver_is_rejected_with_the_fix_named(self):
        # psycopg2 cannot drive an asyncio engine. Failing here with the
        # replacement spelled out beats failing inside SQLAlchemy.
        with pytest.raises(ValueError) as exc:
            normalize_database_url("postgresql+psycopg2://u:p@h/db")
        assert "psycopg2" in str(exc.value)
        assert "postgresql+asyncpg" in str(exc.value)

    def test_unsupported_dialect_lists_the_supported_ones(self):
        with pytest.raises(ValueError) as exc:
            normalize_database_url("oracle://u:p@h/db")
        message = str(exc.value)
        assert "oracle" in message
        assert "postgresql" in message

    @pytest.mark.parametrize("url", ["", "not-a-url", "just some text"])
    def test_non_urls_are_rejected(self, url):
        with pytest.raises(ValueError):
            normalize_database_url(url)
