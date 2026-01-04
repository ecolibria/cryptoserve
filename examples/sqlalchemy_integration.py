#!/usr/bin/env python3
"""
SQLAlchemy Integration Example

Demonstrates transparent field-level encryption with SQLAlchemy models.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import create_engine, Column, String, DateTime, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import sessionmaker

from cryptoserve import CryptoServe

# Initialize CryptoServe
crypto = CryptoServe(
    app_name="sqlalchemy-example",
    team="examples",
    environment="development",
)

# SQLAlchemy setup
Base = declarative_base()
engine = create_engine("sqlite:///:memory:", echo=False)
Session = sessionmaker(bind=engine)


# =============================================================================
# Encrypted Field Mixin
# =============================================================================


class EncryptedFieldMixin:
    """Mixin that provides encrypted field helpers."""

    @staticmethod
    def encrypt_value(value: str, context: str) -> str:
        """Encrypt a string value."""
        if value is None:
            return None
        return crypto.encrypt_string(value, context=context)

    @staticmethod
    def decrypt_value(value: str, context: str) -> str:
        """Decrypt a string value."""
        if value is None:
            return None
        return crypto.decrypt_string(value, context=context)


# =============================================================================
# Models
# =============================================================================


class User(Base, EncryptedFieldMixin):
    """User model with encrypted sensitive fields."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False)
    name = Column(String(100), nullable=False)

    # Encrypted fields (stored as encrypted strings)
    _ssn = Column("ssn_encrypted", String(500), nullable=True)
    _phone = Column("phone_encrypted", String(500), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # SSN property with automatic encryption/decryption
    @hybrid_property
    def ssn(self) -> Optional[str]:
        """Get decrypted SSN."""
        return self.decrypt_value(self._ssn, "user-pii")

    @ssn.setter
    def ssn(self, value: str):
        """Set SSN (automatically encrypted)."""
        self._ssn = self.encrypt_value(value, "user-pii")

    # Phone property with automatic encryption/decryption
    @hybrid_property
    def phone(self) -> Optional[str]:
        """Get decrypted phone number."""
        return self.decrypt_value(self._phone, "user-pii")

    @phone.setter
    def phone(self, value: str):
        """Set phone (automatically encrypted)."""
        self._phone = self.encrypt_value(value, "user-pii")

    def __repr__(self):
        return f"<User(id={self.id}, email={self.email}, name={self.name})>"


class PaymentMethod(Base, EncryptedFieldMixin):
    """Payment method model with encrypted card data."""

    __tablename__ = "payment_methods"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, nullable=False)
    card_type = Column(String(20), nullable=False)  # visa, mastercard, etc.

    # Encrypted fields
    _card_number = Column("card_number_encrypted", String(500), nullable=False)
    _cvv = Column("cvv_encrypted", String(500), nullable=False)
    _expiry = Column("expiry_encrypted", String(500), nullable=False)

    # Non-sensitive fields
    last_four = Column(String(4), nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow)

    @hybrid_property
    def card_number(self) -> Optional[str]:
        return self.decrypt_value(self._card_number, "payment-data")

    @card_number.setter
    def card_number(self, value: str):
        self._card_number = self.encrypt_value(value, "payment-data")
        self.last_four = value[-4:] if value else None

    @hybrid_property
    def cvv(self) -> Optional[str]:
        return self.decrypt_value(self._cvv, "payment-data")

    @cvv.setter
    def cvv(self, value: str):
        self._cvv = self.encrypt_value(value, "payment-data")

    @hybrid_property
    def expiry(self) -> Optional[str]:
        return self.decrypt_value(self._expiry, "payment-data")

    @expiry.setter
    def expiry(self, value: str):
        self._expiry = self.encrypt_value(value, "payment-data")

    def __repr__(self):
        return f"<PaymentMethod(id={self.id}, type={self.card_type}, last_four={self.last_four})>"


class MedicalRecord(Base, EncryptedFieldMixin):
    """Medical record model with HIPAA-compliant encryption."""

    __tablename__ = "medical_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    patient_id = Column(Integer, nullable=False)
    record_type = Column(String(50), nullable=False)

    # PHI fields - encrypted with health-data context
    _diagnosis = Column("diagnosis_encrypted", String(2000), nullable=True)
    _treatment = Column("treatment_encrypted", String(2000), nullable=True)
    _notes = Column("notes_encrypted", String(5000), nullable=True)

    # Non-sensitive metadata
    record_date = Column(DateTime, nullable=False)
    provider = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    @hybrid_property
    def diagnosis(self) -> Optional[str]:
        return self.decrypt_value(self._diagnosis, "health-data")

    @diagnosis.setter
    def diagnosis(self, value: str):
        self._diagnosis = self.encrypt_value(value, "health-data")

    @hybrid_property
    def treatment(self) -> Optional[str]:
        return self.decrypt_value(self._treatment, "health-data")

    @treatment.setter
    def treatment(self, value: str):
        self._treatment = self.encrypt_value(value, "health-data")

    @hybrid_property
    def notes(self) -> Optional[str]:
        return self.decrypt_value(self._notes, "health-data")

    @notes.setter
    def notes(self, value: str):
        self._notes = self.encrypt_value(value, "health-data")


# =============================================================================
# Example Usage
# =============================================================================


def main():
    print("CryptoServe SQLAlchemy Integration Example")
    print("=" * 50)

    # Create tables
    Base.metadata.create_all(engine)
    session = Session()

    # Example 1: Create user with encrypted fields
    print("\n1. Creating user with encrypted PII...")
    user = User(
        email="alice@example.com",
        name="Alice Smith",
        ssn="123-45-6789",  # Automatically encrypted
        phone="+1-555-123-4567",  # Automatically encrypted
    )
    session.add(user)
    session.commit()
    print(f"   Created: {user}")
    print(f"   SSN (decrypted): {user.ssn}")
    print(f"   Phone (decrypted): {user.phone}")

    # Show encrypted values in database
    print(f"\n   Raw database values:")
    print(f"   _ssn: {user._ssn[:50]}...")
    print(f"   _phone: {user._phone[:50]}...")

    # Example 2: Query and automatically decrypt
    print("\n2. Querying user...")
    queried_user = session.query(User).filter_by(email="alice@example.com").first()
    print(f"   Found: {queried_user}")
    print(f"   SSN: {queried_user.ssn}")  # Automatically decrypted
    print(f"   Phone: {queried_user.phone}")  # Automatically decrypted

    # Example 3: Update encrypted field
    print("\n3. Updating encrypted field...")
    queried_user.phone = "+1-555-987-6543"  # Automatically re-encrypted
    session.commit()
    print(f"   New phone: {queried_user.phone}")

    # Example 4: Create payment method
    print("\n4. Creating payment method with encrypted card data...")
    payment = PaymentMethod(
        user_id=user.id,
        card_type="visa",
        card_number="4111111111111111",  # Automatically encrypted
        cvv="123",  # Automatically encrypted
        expiry="12/26",  # Automatically encrypted
    )
    session.add(payment)
    session.commit()
    print(f"   Created: {payment}")
    print(f"   Card number (decrypted): {payment.card_number}")
    print(f"   Last four (not encrypted): {payment.last_four}")
    print(f"   CVV (decrypted): {payment.cvv}")

    # Example 5: Medical record with HIPAA encryption
    print("\n5. Creating medical record (HIPAA-compliant)...")
    record = MedicalRecord(
        patient_id=1,
        record_type="consultation",
        record_date=datetime.utcnow(),
        provider="Dr. Smith",
        diagnosis="Common cold, viral upper respiratory infection",
        treatment="Rest, fluids, OTC medication as needed",
        notes="Patient presented with runny nose and sore throat for 3 days.",
    )
    session.add(record)
    session.commit()
    print(f"   Created medical record ID: {record.id}")
    print(f"   Provider: {record.provider}")
    print(f"   Diagnosis (decrypted): {record.diagnosis[:40]}...")

    # Example 6: Bulk operations
    print("\n6. Bulk insert with encryption...")
    users_to_create = [
        ("bob@example.com", "Bob Jones", "234-56-7890"),
        ("carol@example.com", "Carol Williams", "345-67-8901"),
        ("dave@example.com", "Dave Brown", "456-78-9012"),
    ]

    for email, name, ssn in users_to_create:
        u = User(email=email, name=name, ssn=ssn)
        session.add(u)

    session.commit()
    print(f"   Created {len(users_to_create)} users")

    # Query all users
    all_users = session.query(User).all()
    print(f"\n   All users:")
    for u in all_users:
        print(f"   - {u.name}: SSN={u.ssn}")

    # Example 7: Demonstrate encryption is different each time (salting)
    print("\n7. Demonstrating unique encryption (salting)...")
    same_ssn = "111-22-3333"
    user1 = User(email="test1@example.com", name="Test1")
    user2 = User(email="test2@example.com", name="Test2")
    user1.ssn = same_ssn
    user2.ssn = same_ssn
    print(f"   Same SSN value: {same_ssn}")
    print(f"   User1 encrypted: {user1._ssn[:40]}...")
    print(f"   User2 encrypted: {user2._ssn[:40]}...")
    print(f"   Encrypted values identical: {user1._ssn == user2._ssn}")
    print(f"   (Should be False - each encryption is unique)")

    # Cleanup
    session.close()

    print("\n" + "=" * 50)
    print("SQLAlchemy integration example completed!")
    print("\nKey features demonstrated:")
    print("  - Transparent field-level encryption via hybrid_property")
    print("  - Automatic encryption on write")
    print("  - Automatic decryption on read")
    print("  - Different encryption contexts for different data types")
    print("  - HIPAA-compliant medical record encryption")


if __name__ == "__main__":
    main()
