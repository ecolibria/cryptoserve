#!/usr/bin/env python3
"""
Post-Quantum Cryptography Example

Demonstrates post-quantum cryptographic operations with CryptoServe.
Uses ML-KEM (FIPS 203) and ML-DSA (FIPS 204) algorithms.
"""

from cryptoserve import CryptoServe


def main():
    crypto = CryptoServe(
        app_name="pqc-example",
        team="examples",
    )

    print("CryptoServe Post-Quantum Cryptography Example")
    print("=" * 50)
    print("\nNIST Post-Quantum Standards:")
    print("  - FIPS 203: ML-KEM (Key Encapsulation)")
    print("  - FIPS 204: ML-DSA (Digital Signatures)")
    print("  - FIPS 205: SLH-DSA (Hash-Based Signatures)")

    # Example 1: ML-KEM Key Generation
    print("\n1. ML-KEM Key Generation (FIPS 203)...")
    print("   Generating ML-KEM-768 keypair...")

    mlkem_keypair = crypto.generate_keypair(algorithm="ml-kem-768")
    print(f"   Public key:  {len(mlkem_keypair['public_key'])} bytes")
    print(f"   Private key: {len(mlkem_keypair['private_key'])} bytes")
    print(f"   Algorithm:   ML-KEM-768 (192-bit security)")

    # Example 2: ML-KEM Encapsulation/Decapsulation
    print("\n2. ML-KEM Key Encapsulation...")

    # Sender encapsulates a shared secret using recipient's public key
    encap_result = crypto.encapsulate(
        public_key=mlkem_keypair["public_key"],
        algorithm="ml-kem-768"
    )
    ciphertext = encap_result["ciphertext"]
    shared_secret_sender = encap_result["shared_secret"]
    print(f"   Ciphertext:     {len(ciphertext)} bytes")
    print(f"   Shared secret:  {shared_secret_sender.hex()[:32]}... ({len(shared_secret_sender)} bytes)")

    # Recipient decapsulates using private key
    shared_secret_recipient = crypto.decapsulate(
        ciphertext=ciphertext,
        private_key=mlkem_keypair["private_key"],
        algorithm="ml-kem-768"
    )
    print(f"   Decapsulated:   {shared_secret_recipient.hex()[:32]}...")

    # Verify both parties have the same shared secret
    assert shared_secret_sender == shared_secret_recipient
    print("   Key agreement:  VERIFIED")

    # Example 3: ML-DSA Signature Generation
    print("\n3. ML-DSA Digital Signatures (FIPS 204)...")
    print("   Generating ML-DSA-65 keypair...")

    mldsa_keypair = crypto.generate_keypair(algorithm="ml-dsa-65")
    print(f"   Public key:  {len(mldsa_keypair['public_key'])} bytes")
    print(f"   Private key: {len(mldsa_keypair['private_key'])} bytes")

    # Sign a message
    message = b"This document is quantum-resistant signed."
    signature = crypto.sign_pqc(
        message=message,
        private_key=mldsa_keypair["private_key"],
        algorithm="ml-dsa-65"
    )
    print(f"   Message:     {message.decode()[:40]}...")
    print(f"   Signature:   {len(signature)} bytes")

    # Example 4: ML-DSA Signature Verification
    print("\n4. ML-DSA Signature Verification...")

    is_valid = crypto.verify_pqc(
        message=message,
        signature=signature,
        public_key=mldsa_keypair["public_key"],
        algorithm="ml-dsa-65"
    )
    print(f"   Valid: {is_valid}")
    assert is_valid, "Signature verification failed!"

    # Verify with tampered message
    tampered = b"This document has been modified."
    is_valid_tampered = crypto.verify_pqc(
        message=tampered,
        signature=signature,
        public_key=mldsa_keypair["public_key"],
        algorithm="ml-dsa-65"
    )
    print(f"   Tampered message valid: {is_valid_tampered}")
    assert not is_valid_tampered, "Tampered message should not verify!"

    # Example 5: Compare key sizes
    print("\n5. Key Size Comparison (Classical vs PQC)...")

    sizes = {
        "Algorithm": ["RSA-2048", "ECDSA-P256", "Ed25519", "ML-KEM-768", "ML-DSA-65"],
        "Public Key": ["256 B", "64 B", "32 B", "1,184 B", "1,952 B"],
        "Private Key": ["~1,700 B", "32 B", "64 B", "2,400 B", "4,032 B"],
        "Signature/CT": ["256 B", "64 B", "64 B", "1,088 B", "3,309 B"],
        "Quantum Safe": ["No", "No", "No", "Yes", "Yes"],
    }

    print(f"   {'Algorithm':<12} {'PubKey':>10} {'PrivKey':>10} {'Sig/CT':>10} {'QSafe':>6}")
    print("   " + "-" * 52)
    for i in range(5):
        print(f"   {sizes['Algorithm'][i]:<12} {sizes['Public Key'][i]:>10} "
              f"{sizes['Private Key'][i]:>10} {sizes['Signature/CT'][i]:>10} "
              f"{sizes['Quantum Safe'][i]:>6}")

    # Example 6: Different ML-KEM security levels
    print("\n6. ML-KEM Security Levels...")

    levels = [
        ("ml-kem-512", "128-bit", "Lightweight"),
        ("ml-kem-768", "192-bit", "Recommended"),
        ("ml-kem-1024", "256-bit", "High Security"),
    ]

    for algo, security, desc in levels:
        try:
            kp = crypto.generate_keypair(algorithm=algo)
            print(f"   {algo:<14} {security:<10} {desc:<15} "
                  f"(pub: {len(kp['public_key'])} B, priv: {len(kp['private_key'])} B)")
        except Exception as e:
            print(f"   {algo:<14} Error: {e}")

    # Example 7: Different ML-DSA security levels
    print("\n7. ML-DSA Security Levels...")

    sig_levels = [
        ("ml-dsa-44", "128-bit", "Lightweight"),
        ("ml-dsa-65", "192-bit", "Recommended"),
        ("ml-dsa-87", "256-bit", "High Security"),
    ]

    test_msg = b"Test message for signature"
    for algo, security, desc in sig_levels:
        try:
            kp = crypto.generate_keypair(algorithm=algo)
            sig = crypto.sign_pqc(test_msg, kp["private_key"], algo)
            valid = crypto.verify_pqc(test_msg, sig, kp["public_key"], algo)
            print(f"   {algo:<11} {security:<10} {desc:<15} "
                  f"(sig: {len(sig)} B, valid: {valid})")
        except Exception as e:
            print(f"   {algo:<11} Error: {e}")

    # Example 8: Complete PQC workflow
    print("\n8. Complete Post-Quantum Key Exchange Workflow...")

    # Alice generates ML-KEM keypair
    print("   Alice: Generating ML-KEM keypair...")
    alice_kp = crypto.generate_keypair(algorithm="ml-kem-768")

    # Alice sends public key to Bob (simulated)
    alice_public_key = alice_kp["public_key"]
    print(f"   Alice: Sending public key to Bob ({len(alice_public_key)} bytes)")

    # Bob encapsulates a shared secret using Alice's public key
    print("   Bob:   Encapsulating shared secret...")
    bob_result = crypto.encapsulate(alice_public_key, algorithm="ml-kem-768")
    bob_shared_secret = bob_result["shared_secret"]
    bob_ciphertext = bob_result["ciphertext"]

    # Bob sends ciphertext to Alice
    print(f"   Bob:   Sending ciphertext to Alice ({len(bob_ciphertext)} bytes)")

    # Alice decapsulates to get the same shared secret
    print("   Alice: Decapsulating shared secret...")
    alice_shared_secret = crypto.decapsulate(
        bob_ciphertext,
        alice_kp["private_key"],
        algorithm="ml-kem-768"
    )

    # Both now have the same 256-bit shared secret
    assert alice_shared_secret == bob_shared_secret
    print(f"   Result: Both parties have identical {len(alice_shared_secret)*8}-bit shared secret!")
    print(f"   Secret: {alice_shared_secret.hex()[:32]}...")

    print("\n" + "=" * 50)
    print("All post-quantum examples completed successfully!")
    print("\nNote: These algorithms are quantum-resistant and align with")
    print("NIST FIPS 203/204/205 standards for post-quantum cryptography.")


if __name__ == "__main__":
    main()
