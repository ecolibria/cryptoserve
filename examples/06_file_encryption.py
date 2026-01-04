#!/usr/bin/env python3
"""
File Encryption Example

Demonstrates encrypting and decrypting files with CryptoServe.
"""

import os
import tempfile
from pathlib import Path
from cryptoserve import CryptoServe


def main():
    crypto = CryptoServe(
        app_name="file-encryption-example",
        team="examples",
    )

    print("CryptoServe File Encryption Example")
    print("=" * 50)

    # Create a temporary directory for our examples
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Example 1: Encrypt a text file
        print("\n1. Encrypting a text file...")

        # Create a sample text file
        original_file = tmpdir / "document.txt"
        original_content = "This is a confidential document.\n" * 100
        original_file.write_text(original_content)
        print(f"   Original file: {original_file.name}")
        print(f"   Size: {original_file.stat().st_size} bytes")

        # Encrypt
        encrypted_file = tmpdir / "document.txt.enc"
        plaintext = original_file.read_bytes()
        ciphertext = crypto.encrypt(plaintext, context="documents")
        encrypted_file.write_bytes(ciphertext)
        print(f"   Encrypted file: {encrypted_file.name}")
        print(f"   Size: {encrypted_file.stat().st_size} bytes")

        # Decrypt
        decrypted_file = tmpdir / "document_decrypted.txt"
        ciphertext = encrypted_file.read_bytes()
        decrypted = crypto.decrypt(ciphertext, context="documents")
        decrypted_file.write_bytes(decrypted)
        print(f"   Decrypted file: {decrypted_file.name}")

        # Verify
        assert original_content == decrypted_file.read_text()
        print("   Verification: PASSED")

        # Example 2: Encrypt a binary file
        print("\n2. Encrypting a binary file...")

        # Create a sample binary file (simulated image)
        binary_file = tmpdir / "image.bin"
        binary_content = bytes(range(256)) * 1000  # 256KB of binary data
        binary_file.write_bytes(binary_content)
        print(f"   Original file: {binary_file.name}")
        print(f"   Size: {binary_file.stat().st_size:,} bytes")

        # Encrypt
        encrypted_binary = tmpdir / "image.bin.enc"
        ciphertext = crypto.encrypt(binary_file.read_bytes(), context="documents")
        encrypted_binary.write_bytes(ciphertext)
        print(f"   Encrypted size: {encrypted_binary.stat().st_size:,} bytes")

        # Decrypt and verify
        decrypted_binary = crypto.decrypt(encrypted_binary.read_bytes(), context="documents")
        assert binary_content == decrypted_binary
        print("   Binary integrity: VERIFIED")

        # Example 3: Encrypt with file metadata
        print("\n3. Encrypting with metadata preservation...")

        import json

        # Create file with metadata
        data_file = tmpdir / "data.json"
        file_content = json.dumps({"users": [{"id": 1, "name": "Alice"}]})
        data_file.write_text(file_content)

        # Encrypt with metadata as AAD
        metadata = json.dumps({
            "filename": "data.json",
            "content_type": "application/json",
            "created_by": "alice@example.com"
        }).encode()

        ciphertext = crypto.encrypt(
            data_file.read_bytes(),
            context="documents",
            associated_data=metadata
        )

        print(f"   File: {data_file.name}")
        print(f"   Metadata included as AAD")

        # Decrypt (must provide same metadata)
        decrypted = crypto.decrypt(
            ciphertext,
            context="documents",
            associated_data=metadata
        )
        assert data_file.read_bytes() == decrypted
        print("   Decryption with metadata: SUCCESS")

        # Example 4: Batch file encryption
        print("\n4. Batch file encryption...")

        # Create multiple files
        files_to_encrypt = []
        for i in range(5):
            f = tmpdir / f"file_{i}.txt"
            f.write_text(f"Content of file {i}\n" * 10)
            files_to_encrypt.append(f)
            print(f"   Created: {f.name}")

        # Encrypt all files
        encrypted_dir = tmpdir / "encrypted"
        encrypted_dir.mkdir()

        for f in files_to_encrypt:
            enc_path = encrypted_dir / (f.name + ".enc")
            ciphertext = crypto.encrypt(f.read_bytes(), context="documents")
            enc_path.write_bytes(ciphertext)

        print(f"   Encrypted {len(files_to_encrypt)} files to {encrypted_dir.name}/")

        # Verify all
        for f in files_to_encrypt:
            enc_path = encrypted_dir / (f.name + ".enc")
            decrypted = crypto.decrypt(enc_path.read_bytes(), context="documents")
            assert f.read_bytes() == decrypted
        print("   All files verified: PASSED")

        # Example 5: Large file handling
        print("\n5. Large file handling...")

        large_file = tmpdir / "large_file.bin"
        large_size = 5 * 1024 * 1024  # 5 MB
        large_content = os.urandom(large_size)
        large_file.write_bytes(large_content)
        print(f"   Created large file: {large_size / 1024 / 1024:.1f} MB")

        import time

        # Time encryption
        start = time.time()
        encrypted_large = crypto.encrypt(large_file.read_bytes(), context="documents")
        encrypt_time = time.time() - start
        print(f"   Encryption time: {encrypt_time:.2f}s ({large_size / encrypt_time / 1024 / 1024:.1f} MB/s)")

        # Time decryption
        start = time.time()
        decrypted_large = crypto.decrypt(encrypted_large, context="documents")
        decrypt_time = time.time() - start
        print(f"   Decryption time: {decrypt_time:.2f}s ({large_size / decrypt_time / 1024 / 1024:.1f} MB/s)")

        assert large_content == decrypted_large
        print("   Large file integrity: VERIFIED")

        # Example 6: Secure file deletion pattern
        print("\n6. Secure file handling pattern...")

        sensitive_file = tmpdir / "sensitive.txt"
        sensitive_content = "CONFIDENTIAL: Secret information here"
        sensitive_file.write_text(sensitive_content)

        # Encrypt the file
        encrypted_path = tmpdir / "sensitive.txt.enc"
        encrypted = crypto.encrypt(sensitive_file.read_bytes(), context="user-pii")
        encrypted_path.write_bytes(encrypted)

        # Securely delete original (overwrite before delete)
        sensitive_file.write_bytes(os.urandom(len(sensitive_content)))
        sensitive_file.unlink()
        print(f"   Original securely deleted: {sensitive_file.name}")

        # Later, decrypt when needed
        decrypted = crypto.decrypt(encrypted_path.read_bytes(), context="user-pii")
        assert decrypted.decode() == sensitive_content
        print(f"   Successfully recovered from encrypted version")

    print("\n" + "=" * 50)
    print("All examples completed successfully!")


if __name__ == "__main__":
    main()
