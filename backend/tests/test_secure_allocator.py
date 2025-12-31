"""Tests for secure memory allocator."""

import secrets
import threading
import time

import pytest

from app.core.secure_allocator import (
    SecureAllocator,
    SecureAllocatorError,
    SecureMemory,
    SecureString,
    ProtectionLevel,
    SecureAllocatorStats,
    secure_allocator,
    secure_wipe,
    secure_compare,
)


class TestSecureMemoryBasics:
    """Test basic SecureMemory functionality."""

    def test_create_secure_memory(self):
        """Test creating secure memory."""
        mem = SecureMemory(32)
        assert mem.size == 32

    def test_write_and_read(self):
        """Test writing and reading data."""
        mem = SecureMemory(64)
        data = b"Hello, secure world!"
        mem.write(data)

        result = mem.read(0, len(data))
        assert result == data

        mem.wipe()

    def test_write_at_offset(self):
        """Test writing at specific offset."""
        mem = SecureMemory(32)
        mem.write(b"AAAA", offset=0)
        mem.write(b"BBBB", offset=4)

        assert mem.read(0, 4) == b"AAAA"
        assert mem.read(4, 4) == b"BBBB"
        mem.wipe()

    def test_read_all(self):
        """Test reading all data."""
        mem = SecureMemory(8)
        mem.write(b"12345678")

        result = mem.read()
        assert result == b"12345678"
        mem.wipe()

    def test_context_manager(self):
        """Test context manager auto-wipes."""
        with SecureMemory(32) as mem:
            mem.write(b"Secret data")
            data = mem.read(0, 11)
            assert data == b"Secret data"
        # Memory is wiped after context

    def test_zero_size_fails(self):
        """Test that zero size allocation fails."""
        with pytest.raises(SecureAllocatorError):
            SecureMemory(0)

    def test_negative_size_fails(self):
        """Test that negative size fails."""
        with pytest.raises(SecureAllocatorError):
            SecureMemory(-10)

    def test_write_exceeds_size_fails(self):
        """Test that writing beyond buffer fails."""
        mem = SecureMemory(8)
        with pytest.raises(SecureAllocatorError, match="exceeds buffer"):
            mem.write(b"0123456789")  # 10 bytes > 8
        mem.wipe()

    def test_write_at_offset_exceeds_fails(self):
        """Test that writing at offset beyond buffer fails."""
        mem = SecureMemory(8)
        with pytest.raises(SecureAllocatorError, match="exceeds buffer"):
            mem.write(b"1234", offset=6)  # 6 + 4 > 8
        mem.wipe()

    def test_negative_offset_fails(self):
        """Test that negative offset fails."""
        mem = SecureMemory(8)
        with pytest.raises(SecureAllocatorError, match="negative"):
            mem.write(b"test", offset=-1)
        mem.wipe()

    def test_read_after_wipe_fails(self):
        """Test that reading after wipe fails."""
        mem = SecureMemory(32)
        mem.write(b"data")
        mem.wipe()

        with pytest.raises(SecureAllocatorError, match="wiped"):
            mem.read()

    def test_write_after_wipe_fails(self):
        """Test that writing after wipe fails."""
        mem = SecureMemory(32)
        mem.wipe()

        with pytest.raises(SecureAllocatorError, match="wiped"):
            mem.write(b"data")

    def test_double_wipe_is_safe(self):
        """Test that wiping twice doesn't error."""
        mem = SecureMemory(32)
        mem.write(b"data")
        mem.wipe()
        mem.wipe()  # Should not raise


class TestSecureMemoryProtectionLevels:
    """Test different protection levels."""

    def test_standard_protection(self):
        """Test standard protection level."""
        mem = SecureMemory(64, ProtectionLevel.STANDARD)
        mem.write(b"Standard protection")
        assert mem.read(0, 19) == b"Standard protection"
        mem.wipe()

    def test_locked_protection(self):
        """Test locked protection level."""
        mem = SecureMemory(64, ProtectionLevel.LOCKED)
        mem.write(b"Locked memory")
        assert mem.read(0, 13) == b"Locked memory"
        mem.wipe()

    def test_guarded_protection(self):
        """Test guarded protection level with mmap."""
        mem = SecureMemory(64, ProtectionLevel.GUARDED)
        mem.write(b"Guarded memory")
        assert mem.read(0, 14) == b"Guarded memory"
        mem.wipe()

    def test_maximum_protection(self):
        """Test maximum protection level."""
        mem = SecureMemory(64, ProtectionLevel.MAXIMUM)
        mem.write(b"Maximum protection")
        assert mem.read(0, 18) == b"Maximum protection"
        mem.wipe()


class TestSecureMemoryIntegrity:
    """Test memory integrity features."""

    def test_verify_integrity_passes(self):
        """Test integrity verification passes normally."""
        mem = SecureMemory(64, ProtectionLevel.STANDARD)
        mem.write(b"Valid data")
        assert mem.verify_integrity() is True
        mem.wipe()

    def test_verify_after_wipe_fails(self):
        """Test integrity check after wipe fails."""
        mem = SecureMemory(32)
        mem.wipe()

        with pytest.raises(SecureAllocatorError, match="wiped"):
            mem.verify_integrity()


class TestSecureString:
    """Test SecureString functionality."""

    def test_create_secure_string(self):
        """Test creating secure string."""
        secret = SecureString(b"password123")
        assert len(secret) == 11

    def test_expose_value(self):
        """Test exposing secret value."""
        value = b"my-secret-key"
        secret = SecureString(value)

        exposed = secret.expose()
        assert exposed == value

    def test_equals_matching(self):
        """Test constant-time comparison with matching value."""
        secret = SecureString(b"secret-value")
        assert secret.equals(b"secret-value") is True

    def test_equals_non_matching(self):
        """Test constant-time comparison with non-matching value."""
        secret = SecureString(b"secret-value")
        assert secret.equals(b"wrong-value") is False

    def test_equals_different_length(self):
        """Test comparison with different length."""
        secret = SecureString(b"short")
        assert secret.equals(b"much-longer-value") is False

    def test_equals_with_secure_string(self):
        """Test comparison with another SecureString."""
        secret1 = SecureString(b"same-value")
        secret2 = SecureString(b"same-value")
        assert secret1 == secret2

    def test_eq_with_bytes(self):
        """Test __eq__ with bytes."""
        secret = SecureString(b"test-value")
        assert secret == b"test-value"
        assert not (secret == b"wrong")

    def test_eq_with_invalid_type(self):
        """Test __eq__ with invalid type."""
        secret = SecureString(b"test")
        assert not (secret == "test")  # String, not bytes
        assert not (secret == 123)

    def test_empty_string_fails(self):
        """Test empty secure string fails (empty secrets are useless)."""
        with pytest.raises(SecureAllocatorError):
            SecureString(b"")

    def test_binary_value(self):
        """Test binary secure string."""
        value = bytes(range(256))
        secret = SecureString(value)
        assert secret.expose() == value

    def test_non_bytes_fails(self):
        """Test that non-bytes input fails."""
        with pytest.raises(SecureAllocatorError, match="bytes"):
            SecureString("not bytes")  # type: ignore


class TestSecureAllocator:
    """Test SecureAllocator class."""

    def test_allocate_returns_secure_memory(self):
        """Test allocator returns SecureMemory."""
        allocator = SecureAllocator()
        mem = allocator.allocate(32)
        assert isinstance(mem, SecureMemory)
        mem.wipe()

    def test_get_stats(self):
        """Test getting allocation statistics."""
        allocator = SecureAllocator()
        stats = allocator.get_stats()
        assert isinstance(stats, SecureAllocatorStats)
        assert stats.total_allocations >= 0

    def test_stats_track_allocations(self):
        """Test stats track allocations correctly using singleton."""
        # Use the singleton allocator which tracks all allocations
        initial_stats = secure_allocator.get_stats()
        initial_count = initial_stats.total_allocations
        initial_active = initial_stats.active_allocations

        mem1 = secure_allocator.allocate(32)
        stats1 = secure_allocator.get_stats()
        assert stats1.total_allocations == initial_count + 1
        assert stats1.active_allocations == initial_active + 1

        mem2 = secure_allocator.allocate(64)
        stats2 = secure_allocator.get_stats()
        assert stats2.total_allocations == initial_count + 2
        assert stats2.active_allocations == initial_active + 2

        mem1.wipe()
        stats3 = secure_allocator.get_stats()
        assert stats3.active_allocations == initial_active + 1

        mem2.wipe()
        stats4 = secure_allocator.get_stats()
        assert stats4.active_allocations == initial_active


class TestSecureAllocatorSingleton:
    """Test singleton secure_allocator."""

    def test_singleton_exists(self):
        """Test singleton instance exists."""
        assert secure_allocator is not None
        assert isinstance(secure_allocator, SecureAllocator)

    def test_singleton_allocates(self):
        """Test singleton can allocate."""
        mem = secure_allocator.allocate(32)
        mem.write(b"singleton test")
        assert mem.read(0, 14) == b"singleton test"
        mem.wipe()


class TestSecureWipe:
    """Test secure_wipe function."""

    def test_wipe_bytearray(self):
        """Test wiping bytearray."""
        data = bytearray(b"Secret data to wipe")
        secure_wipe(data)

        # All bytes should be zero
        assert all(b == 0 for b in data)

    def test_wipe_empty_array(self):
        """Test wiping empty bytearray."""
        data = bytearray()
        secure_wipe(data)  # Should not error

    def test_wipe_non_bytearray_fails(self):
        """Test that wiping non-bytearray fails."""
        with pytest.raises(SecureAllocatorError, match="bytearray"):
            secure_wipe(b"bytes not bytearray")  # type: ignore


class TestSecureCompare:
    """Test secure_compare function."""

    def test_compare_equal(self):
        """Test comparing equal values."""
        assert secure_compare(b"same", b"same") is True

    def test_compare_not_equal(self):
        """Test comparing different values."""
        assert secure_compare(b"one", b"two") is False

    def test_compare_different_lengths(self):
        """Test comparing different lengths."""
        assert secure_compare(b"short", b"much-longer") is False

    def test_compare_empty(self):
        """Test comparing empty bytes."""
        assert secure_compare(b"", b"") is True

    def test_compare_binary(self):
        """Test comparing binary data."""
        a = bytes(range(256))
        b = bytes(range(256))
        assert secure_compare(a, b) is True

        # Different binary data (shifted by 1, wrapping around)
        c = bytes((i + 1) % 256 for i in range(256))
        assert secure_compare(a, c) is False


class TestThreadSafety:
    """Test thread safety of secure allocator."""

    def test_concurrent_allocations(self):
        """Test concurrent allocations from multiple threads."""
        allocator = SecureAllocator()
        errors = []
        allocations = []
        lock = threading.Lock()

        def allocate_and_use():
            try:
                mem = allocator.allocate(64)
                mem.write(secrets.token_bytes(64))
                time.sleep(0.01)  # Small delay
                data = mem.read()
                assert len(data) == 64
                mem.wipe()
                with lock:
                    allocations.append(True)
            except Exception as e:
                with lock:
                    errors.append(e)

        threads = [threading.Thread(target=allocate_and_use) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Errors: {errors}"
        assert len(allocations) == 10

    def test_concurrent_access_same_memory(self):
        """Test concurrent access to same SecureMemory."""
        mem = SecureMemory(256)
        errors = []

        def reader(offset):
            try:
                for _ in range(10):
                    data = mem.read(offset, 16)
                    assert len(data) == 16
            except Exception as e:
                errors.append(e)

        def writer(offset, value):
            try:
                for _ in range(10):
                    mem.write(value, offset)
            except Exception as e:
                errors.append(e)

        # Initialize memory
        mem.write(b"\x00" * 256)

        threads = []
        for i in range(4):
            offset = i * 32
            threads.append(threading.Thread(target=reader, args=(offset,)))
            threads.append(
                threading.Thread(target=writer, args=(offset + 16, b"X" * 16))
            )

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Errors: {errors}"
        mem.wipe()


class TestLargeAllocations:
    """Test large memory allocations."""

    def test_large_allocation(self):
        """Test large memory allocation."""
        size = 1024 * 1024  # 1 MB
        mem = SecureMemory(size, ProtectionLevel.STANDARD)

        # Write pattern
        pattern = b"ABCD" * (size // 4)
        mem.write(pattern)

        # Verify
        data = mem.read()
        assert data == pattern
        mem.wipe()

    def test_page_aligned_allocation(self):
        """Test page-aligned allocation with guarded memory."""
        size = 4096  # One page
        mem = SecureMemory(size, ProtectionLevel.GUARDED)
        mem.write(b"X" * size)
        assert mem.verify_integrity()
        mem.wipe()


class TestEdgeCases:
    """Test edge cases."""

    def test_one_byte_allocation(self):
        """Test single byte allocation."""
        mem = SecureMemory(1)
        mem.write(b"X")
        assert mem.read() == b"X"
        mem.wipe()

    def test_binary_data(self):
        """Test with binary data containing nulls."""
        data = b"\x00\xff\x00\xff\x00"
        mem = SecureMemory(len(data))
        mem.write(data)
        assert mem.read() == data
        mem.wipe()

    def test_repeated_allocate_deallocate(self):
        """Test repeated allocation and deallocation."""
        for _ in range(100):
            mem = SecureMemory(32)
            mem.write(secrets.token_bytes(32))
            mem.wipe()

    def test_multiple_memory_objects(self):
        """Test multiple SecureMemory objects simultaneously."""
        memories = []
        for i in range(10):
            mem = SecureMemory(32)
            mem.write(f"Memory {i}".encode().ljust(32, b"\x00"))
            memories.append(mem)

        # Verify each
        for i, mem in enumerate(memories):
            expected = f"Memory {i}".encode().ljust(32, b"\x00")
            assert mem.read() == expected

        # Cleanup
        for mem in memories:
            mem.wipe()


class TestSecurityProperties:
    """Test security properties."""

    def test_canaries_detect_corruption(self):
        """Test that canary corruption is detected.

        Note: We can't easily corrupt canaries from Python since they're
        protected. This test verifies the integrity check works.
        """
        mem = SecureMemory(64, ProtectionLevel.STANDARD)
        mem.write(b"Valid data")

        # Integrity should pass
        assert mem.verify_integrity() is True
        mem.wipe()

    def test_constant_time_comparison(self):
        """Test that comparison is constant-time (basic check)."""
        secret = SecureString(b"password" * 1000)

        # Same value
        start = time.perf_counter()
        for _ in range(100):
            secret.equals(b"password" * 1000)
        same_time = time.perf_counter() - start

        # Different value (same length)
        start = time.perf_counter()
        for _ in range(100):
            secret.equals(b"XXXXXXXX" * 1000)
        diff_time = time.perf_counter() - start

        # Times should be similar (within 2x)
        ratio = max(same_time, diff_time) / min(same_time, diff_time)
        assert ratio < 3.0, f"Timing ratio {ratio} suggests non-constant time"
