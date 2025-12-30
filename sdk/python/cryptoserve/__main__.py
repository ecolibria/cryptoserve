"""
CryptoServe CLI - Run with: python -m cryptoserve

Commands:
    wizard    - Interactive context selection wizard
    verify    - Verify SDK is working correctly
    info      - Show current identity information
"""

import sys
import json


def print_header():
    """Print CLI header."""
    print("\n" + "=" * 60)
    print("  🔐 CryptoServe CLI")
    print("=" * 60 + "\n")


def cmd_verify():
    """Verify SDK health."""
    from cryptoserve import crypto

    print("Checking SDK health...\n")
    result = crypto.verify()

    if result:
        print(f"✅ Status: {result.status}")
        print(f"   Identity: {result.identity_name}")
        print(f"   Latency: {result.latency_ms:.0f}ms")
        print(f"   Contexts: {', '.join(result.allowed_contexts)}")
    else:
        print(f"❌ Status: {result.status}")
        print(f"   Error: {result.error}")

    return 0 if result else 1


def cmd_info():
    """Show identity info."""
    from cryptoserve import crypto

    info = crypto.get_identity()
    print("Current Identity:")
    print(f"  ID: {info['identity_id']}")
    print(f"  Name: {info['name']}")
    print(f"  Team: {info['team']}")
    print(f"  Environment: {info['environment']}")
    print(f"  Allowed Contexts: {', '.join(info['allowed_contexts'])}")
    return 0


def cmd_wizard():
    """Interactive context selection wizard."""
    print_header()
    print("Context Selection Wizard")
    print("Answer a few questions to find the right crypto context.\n")

    # Step 1: Data Type
    print("━" * 50)
    print("STEP 1: What type of data are you protecting?\n")
    data_types = [
        ("pii", "Personal Information (names, emails, addresses)"),
        ("financial", "Financial Data (payment cards, bank accounts)"),
        ("health", "Health Records (medical data, PHI)"),
        ("auth", "Authentication (passwords, tokens, API keys)"),
        ("business", "Business Data (contracts, strategies)"),
        ("general", "General Sensitive Data"),
    ]

    for i, (key, desc) in enumerate(data_types, 1):
        print(f"  {i}. {desc}")

    while True:
        try:
            choice = input("\nSelect [1-6]: ").strip()
            data_type = data_types[int(choice) - 1][0]
            break
        except (ValueError, IndexError):
            print("Please enter a number 1-6")

    # Step 2: Compliance
    print("\n" + "━" * 50)
    print("STEP 2: Which compliance frameworks apply?\n")
    frameworks = [
        ("none", "None / Not Sure"),
        ("soc2", "SOC 2"),
        ("hipaa", "HIPAA (Healthcare)"),
        ("pci", "PCI-DSS (Payment Cards)"),
        ("gdpr", "GDPR (EU Data Protection)"),
        ("multiple", "Multiple Frameworks"),
    ]

    for i, (key, desc) in enumerate(frameworks, 1):
        print(f"  {i}. {desc}")

    while True:
        try:
            choice = input("\nSelect [1-6]: ").strip()
            compliance = frameworks[int(choice) - 1][0]
            break
        except (ValueError, IndexError):
            print("Please enter a number 1-6")

    # Step 3: Threat Level
    print("\n" + "━" * 50)
    print("STEP 3: What's your threat model?\n")
    threats = [
        ("standard", "Standard Protection (opportunistic attackers)"),
        ("elevated", "Elevated Security (organized threats)"),
        ("maximum", "Maximum Security (nation-state level)"),
        ("quantum", "Quantum-Ready (future-proof encryption)"),
    ]

    for i, (key, desc) in enumerate(threats, 1):
        print(f"  {i}. {desc}")

    while True:
        try:
            choice = input("\nSelect [1-4]: ").strip()
            threat = threats[int(choice) - 1][0]
            break
        except (ValueError, IndexError):
            print("Please enter a number 1-4")

    # Step 4: Performance
    print("\n" + "━" * 50)
    print("STEP 4: What are your performance requirements?\n")
    perf_options = [
        ("realtime", "Real-time (<10ms latency required)"),
        ("interactive", "Interactive (<100ms acceptable)"),
        ("batch", "Batch Processing (latency not critical)"),
    ]

    for i, (key, desc) in enumerate(perf_options, 1):
        print(f"  {i}. {desc}")

    while True:
        try:
            choice = input("\nSelect [1-3]: ").strip()
            perf = perf_options[int(choice) - 1][0]
            break
        except (ValueError, IndexError):
            print("Please enter a number 1-3")

    # Generate recommendation
    print("\n" + "=" * 60)
    print("  📋 RECOMMENDATION")
    print("=" * 60 + "\n")

    # Determine algorithm and context name
    if threat == "quantum":
        algorithm = "KYBER-1024-AES-256-GCM"
        quantum_ready = True
    elif threat == "maximum" or compliance in ["hipaa", "pci", "multiple"]:
        algorithm = "AES-256-GCM"
        quantum_ready = False
    elif perf == "realtime":
        algorithm = "ChaCha20-Poly1305"
        quantum_ready = False
    else:
        algorithm = "AES-256-GCM"
        quantum_ready = False

    # Generate context name
    context_parts = []
    if data_type == "pii":
        context_parts.append("user-pii")
    elif data_type == "financial":
        context_parts.append("payment-data")
    elif data_type == "health":
        context_parts.append("phi-records")
    elif data_type == "auth":
        context_parts.append("auth-secrets")
    elif data_type == "business":
        context_parts.append("business-confidential")
    else:
        context_parts.append("sensitive-data")

    context_name = context_parts[0]

    print(f"  Context Name: {context_name}")
    print(f"  Algorithm: {algorithm}")
    print(f"  Quantum Ready: {'Yes' if quantum_ready else 'No'}")
    print()

    # Compliance tags
    compliance_tags = []
    if compliance == "soc2":
        compliance_tags = ["SOC2"]
    elif compliance == "hipaa":
        compliance_tags = ["HIPAA"]
    elif compliance == "pci":
        compliance_tags = ["PCI-DSS"]
    elif compliance == "gdpr":
        compliance_tags = ["GDPR"]
    elif compliance == "multiple":
        compliance_tags = ["SOC2", "GDPR"]

    if compliance_tags:
        print(f"  Compliance: {', '.join(compliance_tags)}")

    # Show code snippet
    print("\n" + "━" * 50)
    print("Code Example:\n")
    print(f'''  from cryptoserve import crypto

  # Encrypt sensitive data
  ciphertext = crypto.encrypt(
      b"sensitive data here",
      context="{context_name}"
  )

  # Decrypt when needed
  plaintext = crypto.decrypt(ciphertext, context="{context_name}")''')

    print("\n" + "━" * 50)
    print("\n💡 Next Steps:")
    print(f"   1. Request access to '{context_name}' context from your admin")
    print("   2. Or create a new context in the dashboard")
    print("   3. Use the code snippet above in your application")
    print()

    # Offer to open dashboard
    try:
        open_dash = input("Open dashboard to create this context? [y/N]: ").strip().lower()
        if open_dash == 'y':
            import webbrowser
            # Try to get server URL from identity
            try:
                from cryptoserve._identity import IDENTITY
                base_url = IDENTITY.get("server_url", "http://localhost:3000")
                # Remove /api if present and construct frontend URL
                if "/api" in base_url:
                    base_url = base_url.replace("/api", "")
                webbrowser.open(f"{base_url}/context-wizard")
            except Exception:
                print("Could not open browser. Visit your CryptoServe dashboard manually.")
    except (EOFError, KeyboardInterrupt):
        pass

    return 0


def cmd_help():
    """Show help."""
    print(__doc__)
    print("Usage: python -m cryptoserve <command>\n")
    print("Commands:")
    print("  wizard    Interactive context selection wizard")
    print("  verify    Verify SDK is working correctly")
    print("  info      Show current identity information")
    print("  help      Show this help message")
    return 0


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        cmd_help()
        return 0

    command = sys.argv[1].lower()

    commands = {
        "wizard": cmd_wizard,
        "verify": cmd_verify,
        "info": cmd_info,
        "help": cmd_help,
        "--help": cmd_help,
        "-h": cmd_help,
    }

    if command in commands:
        return commands[command]()
    else:
        print(f"Unknown command: {command}")
        cmd_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
