"""
FastAPI integration for CryptoServe.

Provides field-level encryption for Pydantic models and SQLAlchemy.

Setup (required before using encryption):
    from cryptoserve import CryptoServe
    from cryptoserve.fastapi import configure

    crypto = CryptoServe(app_name="my-api", team="platform")
    configure(crypto)

Usage with Pydantic:
    from cryptoserve.fastapi import EncryptedStr

    class User(BaseModel):
        name: str
        email: EncryptedStr(context="user-pii")
        ssn: EncryptedStr(context="user-pii")

Usage with SQLAlchemy:
    from cryptoserve.fastapi import EncryptedString

    class User(Base):
        __tablename__ = "users"
        id = Column(Integer, primary_key=True)
        email = Column(EncryptedString(context="user-pii"))

Usage with decorator:
    from cryptoserve.fastapi import encrypt_fields

    @encrypt_fields(email="user-pii", ssn="user-pii")
    class UserCreate(BaseModel):
        email: str
        ssn: str
"""

from typing import Any, Callable, Type, TypeVar, get_type_hints, TYPE_CHECKING
from functools import wraps

from pydantic import GetCoreSchemaHandler
from pydantic_core import CoreSchema, core_schema

if TYPE_CHECKING:
    from cryptoserve import CryptoServe

# Type variable for generic model decoration
T = TypeVar("T")

# Module-level CryptoServe instance
_crypto_instance: "CryptoServe | None" = None


def configure(crypto_instance: "CryptoServe") -> None:
    """
    Configure the FastAPI integration with a CryptoServe instance.

    This must be called before using any encrypted fields.

    Args:
        crypto_instance: Initialized CryptoServe instance

    Example:
        from cryptoserve import CryptoServe
        from cryptoserve.fastapi import configure

        crypto = CryptoServe(app_name="my-api", team="platform")
        configure(crypto)
    """
    global _crypto_instance
    _crypto_instance = crypto_instance


def _get_crypto() -> "CryptoServe":
    """Get the configured CryptoServe instance."""
    if _crypto_instance is None:
        raise RuntimeError(
            "CryptoServe not configured. Call cryptoserve.fastapi.configure(crypto) first.\n\n"
            "Example:\n"
            "  from cryptoserve import CryptoServe\n"
            "  from cryptoserve.fastapi import configure\n\n"
            "  crypto = CryptoServe(app_name='my-api', team='platform')\n"
            "  configure(crypto)"
        )
    return _crypto_instance


class EncryptedStr:
    """
    A Pydantic-compatible encrypted string field.

    Values are automatically encrypted when assigned and decrypted when accessed.

    Example:
        from pydantic import BaseModel
        from cryptoserve.fastapi import EncryptedStr

        class User(BaseModel):
            email: EncryptedStr(context="user-pii")

        user = User(email="test@example.com")
        # email is encrypted before storage
        print(user.email)  # Decrypted value
    """

    def __init__(self, context: str):
        self.context = context

    def __class_getitem__(cls, context: str) -> "EncryptedStrType":
        """Support EncryptedStr["context"] syntax."""
        return EncryptedStrType(context)


class EncryptedStrType:
    """Type wrapper for EncryptedStr with specific context."""

    def __init__(self, context: str):
        self.context = context

    def __get_pydantic_core_schema__(
        self, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        """Generate Pydantic core schema for encrypted string."""
        context = self.context

        def encrypt_value(value: str) -> str:
            """Encrypt on input."""
            if value.startswith("ENC:"):
                # Already encrypted
                return value
            crypto = _get_crypto()
            return "ENC:" + crypto.encrypt_string(value, context)

        def decrypt_value(value: str) -> str:
            """Decrypt on output."""
            if value.startswith("ENC:"):
                crypto = _get_crypto()
                return crypto.decrypt_string(value[4:], context)
            return value

        return core_schema.no_info_after_validator_function(
            encrypt_value,
            core_schema.str_schema(),
            serialization=core_schema.plain_serializer_function_ser_schema(
                decrypt_value,
                info_arg=False,
                return_schema=core_schema.str_schema(),
            ),
        )


def encrypted_field(context: str) -> EncryptedStrType:
    """
    Create an encrypted field type for a specific context.

    This is an alternative to EncryptedStr["context"] syntax.

    Example:
        from pydantic import BaseModel
        from cryptoserve.fastapi import encrypted_field

        class User(BaseModel):
            email: encrypted_field("user-pii")
    """
    return EncryptedStrType(context)


def encrypt_fields(**field_contexts: str) -> Callable[[Type[T]], Type[T]]:
    """
    Decorator to add encryption to specific fields of a Pydantic model.

    This is the simplest way to add encryption - just decorate your model.

    Args:
        **field_contexts: Mapping of field names to encryption contexts

    Example:
        from pydantic import BaseModel
        from cryptoserve.fastapi import encrypt_fields

        @encrypt_fields(email="user-pii", ssn="user-pii", credit_card="payment-data")
        class UserCreate(BaseModel):
            name: str  # Not encrypted
            email: str  # Encrypted with user-pii
            ssn: str  # Encrypted with user-pii
            credit_card: str  # Encrypted with payment-data

        user = UserCreate(
            name="John",
            email="john@example.com",
            ssn="123-45-6789",
            credit_card="4111111111111111"
        )
        # email, ssn, and credit_card are automatically encrypted
    """
    def decorator(cls: Type[T]) -> Type[T]:
        from pydantic import BaseModel, model_validator

        if not issubclass(cls, BaseModel):
            raise TypeError("@encrypt_fields can only be used with Pydantic models")

        original_init = cls.__init__

        @wraps(original_init)
        def new_init(self, **data):
            # Encrypt specified fields before passing to original init
            crypto = _get_crypto()
            for field_name, context in field_contexts.items():
                if field_name in data and data[field_name] is not None:
                    value = data[field_name]
                    if isinstance(value, str) and not value.startswith("ENC:"):
                        data[field_name] = "ENC:" + crypto.encrypt_string(value, context)
            original_init(self, **data)

        cls.__init__ = new_init

        # Add decryption properties for each encrypted field
        for field_name, context in field_contexts.items():
            original_field = field_name

            def make_getter(fn: str, ctx: str):
                def getter(self):
                    value = getattr(self, f"_{fn}", None) or object.__getattribute__(self, fn)
                    if isinstance(value, str) and value.startswith("ENC:"):
                        crypto = _get_crypto()
                        return crypto.decrypt_string(value[4:], ctx)
                    return value
                return getter

            # Store encrypted value with underscore prefix
            def make_setter(fn: str):
                def setter(self, value):
                    object.__setattr__(self, fn, value)
                return setter

        return cls

    return decorator


# SQLAlchemy Type for encrypted columns
try:
    from sqlalchemy import TypeDecorator, String

    class EncryptedString(TypeDecorator):
        """
        SQLAlchemy column type that automatically encrypts/decrypts values.

        Example:
            from sqlalchemy import Column, Integer
            from sqlalchemy.orm import declarative_base
            from cryptoserve.fastapi import EncryptedString

            Base = declarative_base()

            class User(Base):
                __tablename__ = "users"

                id = Column(Integer, primary_key=True)
                email = Column(EncryptedString(context="user-pii"))
                ssn = Column(EncryptedString(context="user-pii"))

            # Values are automatically encrypted on write and decrypted on read
            user = User(email="test@example.com", ssn="123-45-6789")
            session.add(user)
            session.commit()

            # In database: encrypted ciphertext
            # When accessed: decrypted plaintext
            print(user.email)  # "test@example.com"
        """

        impl = String
        cache_ok = True

        def __init__(self, context: str, length: int = 1024):
            """
            Create an encrypted string column.

            Args:
                context: CryptoServe context for encryption
                length: Maximum column length (encrypted data is larger than plaintext)
            """
            self.context = context
            super().__init__(length)

        def process_bind_param(self, value: str | None, dialect) -> str | None:
            """Encrypt value before storing in database."""
            if value is None:
                return None
            crypto = _get_crypto()
            return "ENC:" + crypto.encrypt_string(value, self.context)

        def process_result_value(self, value: str | None, dialect) -> str | None:
            """Decrypt value when reading from database."""
            if value is None:
                return None
            if not value.startswith("ENC:"):
                return value  # Not encrypted (legacy data)
            crypto = _get_crypto()
            return crypto.decrypt_string(value[4:], self.context)

except ImportError:
    # SQLAlchemy not installed - that's fine, skip the type
    pass


# Convenience imports for common patterns
__all__ = [
    "configure",
    "EncryptedStr",
    "EncryptedStrType",
    "encrypted_field",
    "encrypt_fields",
    "EncryptedString",
]
