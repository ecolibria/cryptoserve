"""
CryptoServe CLI - Run with: python -m cryptoserve

Commands:
    configure - Configure SDK with token
    status    - Show current configuration status
    verify    - Verify SDK is working correctly
    info      - Show current identity information
    scan      - Scan for crypto libraries and show inventory
    cbom      - Generate Cryptographic Bill of Materials
    pqc       - Get PQC migration recommendations
    gate      - CI/CD policy gate check
    certs     - Certificate operations (generate-csr, self-signed, parse, verify)
    wizard    - Interactive context selection wizard
"""

import os
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


def cmd_configure():
    """Configure SDK with token."""
    from cryptoserve._identity import get_config_source, reload_config

    # Parse arguments
    token = None
    refresh_token = None
    server_url = None

    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]

        if arg in ["--token", "-t"] and i + 1 < len(sys.argv):
            token = sys.argv[i + 1]
            i += 2
        elif arg in ["--refresh-token", "-r"] and i + 1 < len(sys.argv):
            refresh_token = sys.argv[i + 1]
            i += 2
        elif arg in ["--server", "-s"] and i + 1 < len(sys.argv):
            server_url = sys.argv[i + 1]
            i += 2
        elif not arg.startswith("-") and token is None:
            # Positional token argument
            token = arg
            i += 1
        else:
            print(f"Unknown option: {arg}")
            return 2

    if not token and not refresh_token and not server_url:
        # Interactive mode
        print("CryptoServe Configuration")
        print("=" * 40)
        print()
        print("Set environment variables to configure the SDK:")
        print()
        print("  export CRYPTOSERVE_TOKEN=\"your-access-token\"")
        print("  export CRYPTOSERVE_REFRESH_TOKEN=\"your-refresh-token\"  # Optional")
        print("  export CRYPTOSERVE_SERVER_URL=\"http://localhost:8000\"")
        print()
        print("Or provide token directly:")
        print("  cryptoserve configure --token <token>")
        print()
        return 0

    # Set environment variables (for current session only)
    # User needs to set these permanently in their shell profile
    config_lines = []

    if token:
        os.environ["CRYPTOSERVE_TOKEN"] = token
        config_lines.append(f'export CRYPTOSERVE_TOKEN="{token}"')

    if refresh_token:
        os.environ["CRYPTOSERVE_REFRESH_TOKEN"] = refresh_token
        config_lines.append(f'export CRYPTOSERVE_REFRESH_TOKEN="{refresh_token}"')

    if server_url:
        os.environ["CRYPTOSERVE_SERVER_URL"] = server_url
        config_lines.append(f'export CRYPTOSERVE_SERVER_URL="{server_url}"')

    # Reload config
    reload_config()

    print("Configuration updated for current session.")
    print()
    print("To make permanent, add to your shell profile (~/.bashrc, ~/.zshrc):")
    print()
    for line in config_lines:
        print(f"  {line}")
    print()

    # Verify token if provided
    if token:
        from cryptoserve import crypto
        print("Verifying configuration...")
        result = crypto.verify()
        if result:
            print(f"Token valid. Identity: {result.identity_name}")
        else:
            print(f"Warning: {result.error}")

    return 0


def cmd_status():
    """Show current configuration status."""
    from cryptoserve._identity import (
        IDENTITY,
        AUTO_REFRESH_ENABLED,
        get_config_source,
        get_token,
        get_refresh_token,
        get_server_url,
        is_configured,
    )

    print("CryptoServe SDK Status")
    print("=" * 50)
    print()

    # Configuration source
    source = get_config_source()
    print(f"Configuration Source: {source}")
    print()

    # Server
    print(f"Server URL: {get_server_url()}")
    print()

    # Token status
    token = get_token()
    if token:
        # Mask token
        if len(token) > 20:
            masked = token[:8] + "..." + token[-4:]
        else:
            masked = token[:4] + "..." if len(token) > 4 else "***"
        print(f"Access Token: {masked}")

        # Try to parse token expiry
        try:
            import base64
            parts = token.split(".")
            if len(parts) == 3:
                payload = parts[1]
                padding = 4 - len(payload) % 4
                if padding != 4:
                    payload += "=" * padding
                decoded = base64.urlsafe_b64decode(payload)
                claims = json.loads(decoded)
                if "exp" in claims:
                    from datetime import datetime, timezone
                    exp = datetime.fromtimestamp(claims["exp"], tz=timezone.utc)
                    now = datetime.now(timezone.utc)
                    remaining = (exp - now).total_seconds()
                    if remaining > 0:
                        hours = int(remaining // 3600)
                        mins = int((remaining % 3600) // 60)
                        print(f"  Expires in: {hours}h {mins}m")
                    else:
                        print("  Status: EXPIRED")
                if "sub" in claims:
                    print(f"  Subject: {claims['sub']}")
        except Exception:
            pass
    else:
        print("Access Token: Not configured")

    # Refresh token
    refresh = get_refresh_token()
    if refresh:
        if len(refresh) > 20:
            masked = refresh[:8] + "..." + refresh[-4:]
        else:
            masked = refresh[:4] + "..." if len(refresh) > 4 else "***"
        print(f"Refresh Token: {masked}")
    else:
        print("Refresh Token: Not configured")

    print(f"Auto-Refresh: {'Enabled' if AUTO_REFRESH_ENABLED else 'Disabled'}")
    print()

    # Identity info
    print("Application Info:")
    print(f"  Name: {IDENTITY.get('name', 'Not set')}")
    print(f"  Team: {IDENTITY.get('team', 'Not set')}")
    print(f"  Environment: {IDENTITY.get('environment', 'Not set')}")
    contexts = IDENTITY.get("allowed_contexts", [])
    if contexts:
        print(f"  Allowed Contexts: {', '.join(contexts)}")
    print()

    # Overall status
    if is_configured():
        print("SDK Status: Configured")
        # Try to verify
        from cryptoserve import crypto
        result = crypto.verify()
        if result:
            print(f"  Connection: OK (latency: {result.latency_ms:.0f}ms)")
        else:
            print(f"  Connection: Failed ({result.error})")
    else:
        print("SDK Status: Not configured")
        print("  Run 'cryptoserve configure' for setup instructions")

    return 0


def cmd_certs():
    """Certificate operations."""
    if len(sys.argv) < 3:
        print("Certificate Commands:")
        print()
        print("  cryptoserve certs generate-csr --cn <common-name> [options]")
        print("    Generate a Certificate Signing Request")
        print("    Options:")
        print("      --org <organization>    Organization name")
        print("      --country <code>        Country code (2 letters)")
        print("      --key-type ec|rsa       Key type (default: ec)")
        print("      --key-size <bits>       Key size (default: 256 for EC)")
        print("      --san <domain>          Subject Alternative Name (repeatable)")
        print("      --output <prefix>       Output file prefix")
        print()
        print("  cryptoserve certs self-signed --cn <common-name> [options]")
        print("    Generate a self-signed certificate")
        print("    Options:")
        print("      --org <organization>    Organization name")
        print("      --days <number>         Validity period (default: 365)")
        print("      --ca                    Create as CA certificate")
        print("      --san <domain>          Subject Alternative Name")
        print("      --output <prefix>       Output file prefix")
        print()
        print("  cryptoserve certs parse <cert.pem>")
        print("    Parse and display certificate information")
        print()
        print("  cryptoserve certs verify <cert.pem> [--issuer <ca.pem>]")
        print("    Verify a certificate")
        return 0

    subcommand = sys.argv[2].lower()

    if subcommand == "generate-csr":
        return _cmd_certs_generate_csr()
    elif subcommand == "self-signed":
        return _cmd_certs_self_signed()
    elif subcommand == "parse":
        return _cmd_certs_parse()
    elif subcommand == "verify":
        return _cmd_certs_verify()
    else:
        print(f"Unknown certs subcommand: {subcommand}")
        return 1


def _cmd_certs_generate_csr():
    """Generate CSR."""
    from cryptoserve_client import CryptoClient
    from cryptoserve._identity import get_server_url, get_token

    # Parse arguments
    cn = None
    org = None
    country = None
    key_type = "ec"
    key_size = 256
    san_domains = []
    output_prefix = None

    i = 3
    while i < len(sys.argv):
        arg = sys.argv[i]

        if arg == "--cn" and i + 1 < len(sys.argv):
            cn = sys.argv[i + 1]
            i += 2
        elif arg == "--org" and i + 1 < len(sys.argv):
            org = sys.argv[i + 1]
            i += 2
        elif arg == "--country" and i + 1 < len(sys.argv):
            country = sys.argv[i + 1]
            i += 2
        elif arg == "--key-type" and i + 1 < len(sys.argv):
            key_type = sys.argv[i + 1]
            i += 2
        elif arg == "--key-size" and i + 1 < len(sys.argv):
            key_size = int(sys.argv[i + 1])
            i += 2
        elif arg == "--san" and i + 1 < len(sys.argv):
            san_domains.append(sys.argv[i + 1])
            i += 2
        elif arg in ["--output", "-o"] and i + 1 < len(sys.argv):
            output_prefix = sys.argv[i + 1]
            i += 2
        else:
            i += 1

    if not cn:
        print("Error: --cn (common name) is required")
        return 1

    client = CryptoClient(server_url=get_server_url(), token=get_token())

    try:
        result = client.generate_csr(
            common_name=cn,
            organization=org,
            country=country,
            key_type=key_type,
            key_size=key_size,
            san_domains=san_domains if san_domains else None,
        )

        if output_prefix:
            # Save to files
            with open(f"{output_prefix}.csr", "w") as f:
                f.write(result["csr_pem"])
            with open(f"{output_prefix}.key", "w") as f:
                f.write(result["private_key_pem"])
            print(f"CSR saved to: {output_prefix}.csr")
            print(f"Private key saved to: {output_prefix}.key")
            print()
            print("KEEP THE PRIVATE KEY SECURE!")
        else:
            print("Certificate Signing Request:")
            print(result["csr_pem"])
            print()
            print("Private Key (KEEP SECURE):")
            print(result["private_key_pem"])

        return 0

    except Exception as e:
        print(f"Error: {e}")
        return 1


def _cmd_certs_self_signed():
    """Generate self-signed certificate."""
    from cryptoserve_client import CryptoClient
    from cryptoserve._identity import get_server_url, get_token

    # Parse arguments
    cn = None
    org = None
    country = None
    days = 365
    is_ca = False
    san_domains = []
    output_prefix = None

    i = 3
    while i < len(sys.argv):
        arg = sys.argv[i]

        if arg == "--cn" and i + 1 < len(sys.argv):
            cn = sys.argv[i + 1]
            i += 2
        elif arg == "--org" and i + 1 < len(sys.argv):
            org = sys.argv[i + 1]
            i += 2
        elif arg == "--country" and i + 1 < len(sys.argv):
            country = sys.argv[i + 1]
            i += 2
        elif arg == "--days" and i + 1 < len(sys.argv):
            days = int(sys.argv[i + 1])
            i += 2
        elif arg == "--ca":
            is_ca = True
            i += 1
        elif arg == "--san" and i + 1 < len(sys.argv):
            san_domains.append(sys.argv[i + 1])
            i += 2
        elif arg in ["--output", "-o"] and i + 1 < len(sys.argv):
            output_prefix = sys.argv[i + 1]
            i += 2
        else:
            i += 1

    if not cn:
        print("Error: --cn (common name) is required")
        return 1

    client = CryptoClient(server_url=get_server_url(), token=get_token())

    try:
        result = client.generate_self_signed_cert(
            common_name=cn,
            organization=org,
            country=country,
            validity_days=days,
            is_ca=is_ca,
            san_domains=san_domains if san_domains else None,
        )

        if output_prefix:
            with open(f"{output_prefix}.crt", "w") as f:
                f.write(result["certificate_pem"])
            with open(f"{output_prefix}.key", "w") as f:
                f.write(result["private_key_pem"])
            print(f"Certificate saved to: {output_prefix}.crt")
            print(f"Private key saved to: {output_prefix}.key")
        else:
            print("Certificate:")
            print(result["certificate_pem"])
            print()
            print("Private Key (KEEP SECURE):")
            print(result["private_key_pem"])

        return 0

    except Exception as e:
        print(f"Error: {e}")
        return 1


def _cmd_certs_parse():
    """Parse certificate."""
    from cryptoserve_client import CryptoClient
    from cryptoserve._identity import get_server_url, get_token

    if len(sys.argv) < 4:
        print("Usage: cryptoserve certs parse <cert.pem>")
        return 1

    cert_file = sys.argv[3]

    try:
        with open(cert_file, "r") as f:
            cert_pem = f.read()
    except FileNotFoundError:
        print(f"Error: File not found: {cert_file}")
        return 1

    client = CryptoClient(server_url=get_server_url(), token=get_token())

    try:
        result = client.parse_certificate(cert_pem)

        print("Certificate Information:")
        print("=" * 50)
        print()

        if "subject" in result:
            print("Subject:")
            for key, value in result["subject"].items():
                print(f"  {key}: {value}")
            print()

        if "issuer" in result:
            print("Issuer:")
            for key, value in result["issuer"].items():
                print(f"  {key}: {value}")
            print()

        if "validity" in result:
            print("Validity:")
            print(f"  Not Before: {result['validity'].get('not_before', 'N/A')}")
            print(f"  Not After: {result['validity'].get('not_after', 'N/A')}")
            print()

        if "key_info" in result:
            print("Public Key:")
            print(f"  Algorithm: {result['key_info'].get('algorithm', 'N/A')}")
            print(f"  Size: {result['key_info'].get('size', 'N/A')} bits")
            print()

        if "san" in result and result["san"]:
            print("Subject Alternative Names:")
            for san in result["san"]:
                print(f"  - {san}")
            print()

        if "serial_number" in result:
            print(f"Serial Number: {result['serial_number']}")

        if "fingerprint" in result:
            print(f"SHA-256 Fingerprint: {result['fingerprint']}")

        return 0

    except Exception as e:
        print(f"Error: {e}")
        return 1


def _cmd_certs_verify():
    """Verify certificate."""
    from cryptoserve_client import CryptoClient
    from cryptoserve._identity import get_server_url, get_token

    if len(sys.argv) < 4:
        print("Usage: cryptoserve certs verify <cert.pem> [--issuer <ca.pem>]")
        return 1

    cert_file = sys.argv[3]
    issuer_file = None

    i = 4
    while i < len(sys.argv):
        if sys.argv[i] == "--issuer" and i + 1 < len(sys.argv):
            issuer_file = sys.argv[i + 1]
            i += 2
        else:
            i += 1

    try:
        with open(cert_file, "r") as f:
            cert_pem = f.read()
    except FileNotFoundError:
        print(f"Error: File not found: {cert_file}")
        return 1

    issuer_pem = None
    if issuer_file:
        try:
            with open(issuer_file, "r") as f:
                issuer_pem = f.read()
        except FileNotFoundError:
            print(f"Error: File not found: {issuer_file}")
            return 1

    client = CryptoClient(server_url=get_server_url(), token=get_token())

    try:
        result = client.verify_certificate(
            certificate_pem=cert_pem,
            issuer_certificate_pem=issuer_pem,
            check_expiry=True,
        )

        if result.get("valid"):
            print("Certificate is VALID")
        else:
            print("Certificate is INVALID")

        if result.get("errors"):
            print()
            print("Errors:")
            for error in result["errors"]:
                print(f"  - {error}")

        if result.get("warnings"):
            print()
            print("Warnings:")
            for warning in result["warnings"]:
                print(f"  - {warning}")

        return 0 if result.get("valid") else 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


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


def cmd_scan():
    """Scan for crypto libraries."""
    from cryptoserve import init

    print("Scanning for cryptographic libraries...\n")
    result = init(report_to_platform=False, async_reporting=False)

    if not result.success:
        print(f"Scan failed: {result.error}")
        return 1

    print(f"Detected {len(result.libraries)} crypto libraries:\n")

    for lib in result.libraries:
        status = ""
        if lib.get("is_deprecated"):
            status = " (DEPRECATED)"
        elif lib.get("quantum_risk") in ["high", "critical"]:
            status = " (QUANTUM VULNERABLE)"

        print(f"  {lib['name']}{status}")
        if lib.get("version"):
            print(f"    Version: {lib['version']}")
        print(f"    Category: {lib['category']}")
        print(f"    Quantum Risk: {lib['quantum_risk']}")
        print(f"    Algorithms: {', '.join(lib.get('algorithms', []))}")
        print()

    # Summary
    vulnerable = len(result.quantum_vulnerable)
    deprecated = len(result.deprecated)

    if deprecated > 0:
        print(f"Deprecated libraries: {deprecated}")
    if vulnerable > 0:
        print(f"Quantum-vulnerable libraries: {vulnerable}")

    return 0


def cmd_cbom():
    """Generate CBOM."""
    from cryptoserve import export_cbom

    # Parse format argument
    format_arg = "json"
    output_file = None

    for i, arg in enumerate(sys.argv[2:], 2):
        if arg in ["--format", "-f"] and i + 1 < len(sys.argv):
            format_arg = sys.argv[i + 1]
        elif arg in ["--output", "-o"] and i + 1 < len(sys.argv):
            output_file = sys.argv[i + 1]
        elif arg in ["json", "cyclonedx", "spdx"]:
            format_arg = arg

    print(f"Generating CBOM ({format_arg} format)...\n")

    try:
        result = export_cbom(format=format_arg)

        if output_file:
            result.save(output_file)
            print(f"CBOM saved to: {output_file}")
        else:
            print(result.to_json())

        print(f"\nQuantum Readiness Score: {result.score:.0f}%")
        print(f"Risk Level: {result.risk_level}")

        return 0

    except Exception as e:
        print(f"Failed to generate CBOM: {e}")
        return 1


def cmd_pqc():
    """Get PQC recommendations."""
    from cryptoserve import get_pqc_recommendations

    # Parse data profile argument
    data_profile = "general"

    for i, arg in enumerate(sys.argv[2:], 2):
        if arg in ["--profile", "-p"] and i + 1 < len(sys.argv):
            data_profile = sys.argv[i + 1]
        elif arg in ["healthcare", "national_security", "financial", "general", "short_lived"]:
            data_profile = arg

    print(f"Analyzing PQC readiness (profile: {data_profile})...\n")

    try:
        result = get_pqc_recommendations(data_profile=data_profile)

        # Urgency banner
        urgency_colors = {
            "critical": "!!! CRITICAL !!!",
            "high": "!! HIGH !!",
            "medium": "! MEDIUM !",
            "low": "LOW",
            "none": "NONE",
        }
        print("=" * 60)
        print(f"  Migration Urgency: {urgency_colors.get(result.urgency, result.urgency)}")
        print(f"  Quantum Readiness Score: {result.score:.0f}%")
        print("=" * 60)

        # SNDL warning
        if result.sndl_vulnerable:
            print("\nSNDL RISK: Your data may be vulnerable to")
            print("           'Store Now, Decrypt Later' attacks!")

        # Key findings
        if result.key_findings:
            print("\nKey Findings:")
            for finding in result.key_findings:
                print(f"  - {finding}")

        # Recommendations
        if result.kem_recommendations:
            print("\nKEM (Key Exchange) Recommendations:")
            for rec in result.kem_recommendations:
                print(f"  {rec['current_algorithm']} -> {rec['recommended_algorithm']}")
                print(f"    Standard: {rec['fips_standard']}")
                print(f"    Rationale: {rec['rationale']}")

        if result.signature_recommendations:
            print("\nSignature Recommendations:")
            for rec in result.signature_recommendations:
                print(f"  {rec['current_algorithm']} -> {rec['recommended_algorithm']}")
                print(f"    Standard: {rec['fips_standard']}")

        # Next steps
        if result.next_steps:
            print("\nNext Steps:")
            for i, step in enumerate(result.next_steps[:5], 1):
                print(f"  {i}. {step}")

        return 0

    except Exception as e:
        print(f"Failed to get recommendations: {e}")
        return 1


def cmd_gate():
    """Run CI/CD policy gate check."""
    import json as json_module

    from cryptoserve._gate import run_gate, format_text_output

    # Parse arguments
    paths = []
    policy = "standard"
    output_format = "text"
    fail_on = "violations"
    staged_only = False
    include_deps = False

    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]

        if arg in ["--policy", "-p"] and i + 1 < len(sys.argv):
            policy = sys.argv[i + 1]
            i += 2
        elif arg in ["--format", "-f"] and i + 1 < len(sys.argv):
            output_format = sys.argv[i + 1]
            i += 2
        elif arg in ["--fail-on"] and i + 1 < len(sys.argv):
            fail_on = sys.argv[i + 1]
            i += 2
        elif arg == "--staged":
            staged_only = True
            i += 1
        elif arg == "--include-deps":
            include_deps = True
            i += 1
        elif arg in ["strict", "standard", "permissive"]:
            policy = arg
            i += 1
        elif arg in ["json", "sarif", "text"]:
            output_format = arg
            i += 1
        elif arg.startswith("-"):
            print(f"Unknown option: {arg}")
            return 2
        else:
            paths.append(arg)
            i += 1

    # Default to current directory
    if not paths and not staged_only:
        paths = ["."]

    try:
        result = run_gate(
            paths=paths if paths else None,
            policy=policy,
            staged_only=staged_only,
            fail_on=fail_on,
            include_deps=include_deps,
        )

        # Output based on format
        if output_format == "json":
            print(json_module.dumps(result.to_dict(), indent=2))
        elif output_format == "sarif":
            print(json_module.dumps(result.to_sarif(), indent=2))
        else:
            print(format_text_output(result))

        return result.exit_code

    except ValueError as e:
        print(f"Configuration error: {e}")
        return 2
    except Exception as e:
        print(f"Gate check failed: {e}")
        return 2


def cmd_help():
    """Show help."""
    print(__doc__)
    print("Usage: python -m cryptoserve <command>\n")
    print("Commands:")
    print("  configure Configure SDK with token")
    print("            Options: --token <token>")
    print("                     --refresh-token <refresh-token>")
    print("                     --server <url>")
    print("  status    Show current configuration status")
    print("  verify    Verify SDK is working correctly")
    print("  info      Show current identity information")
    print("  scan      Scan for crypto libraries")
    print("  cbom      Generate Cryptographic Bill of Materials")
    print("            Options: --format json|cyclonedx|spdx")
    print("                     --output <file>")
    print("  pqc       Get PQC migration recommendations")
    print("            Options: --profile healthcare|financial|general|short_lived")
    print("  gate      CI/CD policy gate check")
    print("            Options: --policy strict|standard|permissive")
    print("                     --format text|json|sarif")
    print("                     --fail-on violations|warnings")
    print("                     --staged (scan git staged files only)")
    print("                     --include-deps (scan dependency files)")
    print("  certs     Certificate operations")
    print("            Sub-commands:")
    print("              generate-csr   Generate Certificate Signing Request")
    print("              self-signed    Generate self-signed certificate")
    print("              parse          Parse and display certificate info")
    print("              verify         Verify a certificate")
    print("  wizard    Interactive context selection wizard")
    print("  help      Show this help message")
    return 0


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        cmd_help()
        return 0

    command = sys.argv[1].lower()

    commands = {
        "configure": cmd_configure,
        "status": cmd_status,
        "wizard": cmd_wizard,
        "verify": cmd_verify,
        "info": cmd_info,
        "scan": cmd_scan,
        "cbom": cmd_cbom,
        "pqc": cmd_pqc,
        "gate": cmd_gate,
        "certs": cmd_certs,
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
