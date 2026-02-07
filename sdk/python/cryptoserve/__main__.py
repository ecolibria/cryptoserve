"""
CryptoServe CLI - Run with: python -m cryptoserve

Commands:
    login     - Login to CryptoServe (opens browser)
    promote   - Check promotion readiness or request promotion
    status    - Show current configuration status
    configure - Configure SDK with token (for encryption operations)
    verify    - Verify SDK is working correctly
    info      - Show current identity information
    contexts  - List and search encryption contexts
    scan      - Scan for crypto libraries and show inventory
    cbom      - Generate Cryptographic Bill of Materials
    pqc       - Get PQC migration recommendations
    gate      - CI/CD policy gate check
    certs     - Certificate operations (generate-csr, self-signed, parse, verify)
    wizard    - Interactive context selection wizard

Offline Tools (no server required):
    encrypt       - Encrypt a string or file with a password
    decrypt       - Decrypt a string or file with a password
    hash-password - Hash a password (scrypt or PBKDF2)
    token         - Create a JWT token

Examples:
    cryptoserve login                              # Login via browser
    cryptoserve contexts                           # List available contexts
    cryptoserve contexts "email"                   # Search for contexts
    cryptoserve contexts -e user-pii               # Show usage example
    cryptoserve promote my-backend-app             # Check promotion readiness
    cryptoserve promote my-backend-app --confirm   # Promote to production
    cryptoserve promote my-backend-app --expedite  # Request expedited approval
    cryptoserve encrypt "hello" --password secret  # Encrypt a string
    cryptoserve hash-password                      # Hash a password (interactive)
    cryptoserve token --key my-key --payload '{}'  # Create JWT token
"""

import os
import sys
import json

# Import CLI styling
try:
    from cryptoserve._cli_style import (
        Style, Colors, Icons, Box,
        header, subheader, section, divider,
        success, error, warning, info, dim, bold,
        label_value, table_header, table_row,
        progress_bar, status_badge, code_block,
        brand_header, compact_header, indent,
    )
    STYLED = True
except ImportError:
    STYLED = False

    # Fallback functions if styling not available
    def success(t): return f"✓ {t}"
    def error(t): return f"✗ {t}"
    def warning(t): return f"⚠ {t}"
    def info(t): return f"ℹ {t}"
    def dim(t): return t
    def bold(t): return t
    def divider(w=60): return "-" * w
    def compact_header(c=""): return f"\nCRYPTOSERVE > {c}\n" if c else "\nCRYPTOSERVE\n"


def print_header():
    """Print CLI header."""
    if STYLED:
        print(brand_header())
    else:
        print("\n" + "=" * 60)
        print("  CryptoServe CLI")
        print("=" * 60 + "\n")


# Credentials storage location
def _get_credentials_path():
    """Get path to stored credentials."""
    home = os.path.expanduser("~")
    creds_dir = os.path.join(home, ".cryptoserve")
    os.makedirs(creds_dir, exist_ok=True)
    return os.path.join(creds_dir, "credentials.json")


def _load_credentials():
    """Load stored credentials."""
    path = _get_credentials_path()
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_credentials(creds: dict):
    """Save credentials."""
    path = _get_credentials_path()
    with open(path, "w") as f:
        json.dump(creds, f, indent=2)
    os.chmod(path, 0o600)  # Restrict permissions


def _get_session_cookie():
    """Get session cookie for authenticated requests."""
    creds = _load_credentials()
    return creds.get("session_cookie")


def _get_cli_server_url():
    """Get server URL for CLI commands."""
    creds = _load_credentials()
    return creds.get("server_url", os.getenv("CRYPTOSERVE_SERVER_URL", "http://localhost:8000"))


# Alias for convenience
_get_server_url = _get_cli_server_url


def cmd_login():
    """Login to CryptoServe via browser."""
    import webbrowser
    import http.server
    import urllib.parse
    import threading
    import requests

    # Parse arguments
    server_url = "http://localhost:8000"
    use_dev = False
    manual_cookie = None

    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ["--server", "-s"] and i + 1 < len(sys.argv):
            server_url = sys.argv[i + 1]
            i += 2
        elif arg == "--dev":
            use_dev = True
            i += 1
        elif arg == "--cookie" and i + 1 < len(sys.argv):
            manual_cookie = sys.argv[i + 1]
            i += 2
        else:
            i += 1

    # Handle manual cookie setting
    if manual_cookie:
        creds = _load_credentials()
        creds["session_cookie"] = manual_cookie
        creds["server_url"] = server_url
        _save_credentials(creds)
        print(success("Session cookie saved."))
        return 0

    print(compact_header("LOGIN"))
    print(divider())

    # Check if server is in dev mode
    try:
        print(dim(f"  Connecting to {server_url}..."))
        status_resp = requests.get(f"{server_url}/auth/status", timeout=5)
        if status_resp.ok:
            auth_status = status_resp.json()
            if auth_status.get("devMode"):
                use_dev = True
                print(info("Server is in development mode"))
    except requests.exceptions.ConnectionError:
        print(error(f"Cannot connect to server at {server_url}"))
        print(dim("  Make sure the server is running."))
        return 1
    except Exception:
        pass

    print()

    # We'll use a simple callback server to capture the auth
    callback_port = 9876
    auth_result = {"success": False, "cookie": None, "user": None}

    class CallbackHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass  # Suppress logging

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)

            if "session" in params:
                auth_result["success"] = True
                auth_result["cookie"] = params["session"][0]
                auth_result["user"] = params.get("user", [""])[0]

                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"""
                    <html><body style="font-family: system-ui; text-align: center; padding: 50px;">
                    <h1>Login Successful!</h1>
                    <p>You can close this window and return to the terminal.</p>
                    </body></html>
                """)
            else:
                self.send_response(400)
                self.end_headers()

    # Start callback server
    try:
        httpd = http.server.HTTPServer(("127.0.0.1", callback_port), CallbackHandler)
    except OSError:
        print(error(f"Port {callback_port} is in use. Please try again."))
        return 1

    def run_server():
        httpd.handle_request()  # Handle single request then stop

    server_thread = threading.Thread(target=run_server)
    server_thread.start()

    # Build login URL based on mode
    callback_url = f"http://127.0.0.1:{callback_port}"
    if use_dev:
        login_url = f"{server_url}/auth/dev-login?cli_callback={callback_url}"
        print(info("Using development mode authentication"))
    else:
        login_url = f"{server_url}/auth/github?cli_callback={callback_url}"
        print(info("Opening browser for GitHub authentication"))

    print()
    print(dim(f"  URL: {login_url}"))
    print()

    webbrowser.open(login_url)

    # Wait for callback with visual feedback
    print(dim("  Waiting for authentication..."))
    server_thread.join(timeout=120)  # 2 minute timeout

    print()
    if auth_result["success"]:
        # Save credentials
        creds = _load_credentials()
        creds["session_cookie"] = auth_result["cookie"]
        creds["server_url"] = server_url
        creds["user"] = auth_result["user"]
        _save_credentials(creds)

        print(divider())
        print(success(f"Authenticated as {bold(auth_result['user'])}"))
        print()
        print(dim("  You can now use CLI commands:"))
        print(dim("    cryptoserve promote my-app"))
        print(dim("    cryptoserve promote my-app --confirm"))
        print()
        return 0
    else:
        print(divider())
        print(error("Authentication timed out or was cancelled"))
        print()
        print(dim("  Alternatives:"))
        print(dim(f"    1. Visit the URL manually: {login_url}"))
        print(dim("    2. Set session manually: cryptoserve login --cookie <token>"))
        print()
        return 1


def cmd_logout():
    """Logout from CryptoServe."""
    print(compact_header("LOGOUT"))

    path = _get_credentials_path()
    if os.path.exists(path):
        os.remove(path)
        print(f"  {success('Logged out successfully')}")
        print()
        print(dim("  Credentials have been removed."))
    else:
        print(f"  {dim('Not logged in')}")

    print()
    return 0


def cmd_verify():
    """Verify SDK health."""
    import time
    import requests as req

    print(compact_header("VERIFY"))
    print(dim("  Checking SDK health..."))
    print()

    server_url = _get_cli_server_url()

    print(divider())
    print()

    try:
        start = time.time()
        resp = req.get(f"{server_url}/health", timeout=10)
        latency_ms = (time.time() - start) * 1000
        if resp.status_code == 200:
            data = resp.json()
            print(f"  {success('SDK Connected')}")
            print()
            print(f"  {bold('Server:')}   {server_url}")
            print(f"  {bold('Status:')}   {data.get('status', 'ok')}")
            print(f"  {bold('Latency:')}  {latency_ms:.0f}ms")
            print()
            return 0
        else:
            print(f"  {error('Server returned ' + str(resp.status_code))}")
            print()
            return 1
    except req.exceptions.ConnectionError:
        print(f"  {error('Cannot connect to server')}")
        print(f"  {dim(f'  Server URL: {server_url}')}")
        print()
        print(dim("  Make sure the server is running:"))
        print(dim("    docker compose up -d"))
        print()
        return 1
    except Exception as e:
        print(f"  {error(f'Health check failed: {e}')}")
        print()
        return 1


def cmd_info():
    """Show identity info."""
    import requests as req

    print(compact_header("INFO"))

    server_url = _get_cli_server_url()
    session_cookie = _get_session_cookie()

    if not session_cookie:
        print(f"  {error('Not logged in. Run: cryptoserve login')}")
        print()
        return 1

    try:
        resp = req.get(
            f"{server_url}/api/v1/identity",
            cookies={"session": session_cookie},
            timeout=10,
        )
        if resp.status_code == 401:
            print(f"  {error('Session expired. Run: cryptoserve login')}")
            print()
            return 1
        resp.raise_for_status()
        identity = resp.json()
    except req.exceptions.ConnectionError:
        print(f"  {error(f'Cannot connect to server at {server_url}')}")
        print()
        return 1
    except Exception as e:
        print(f"  {error('Failed to get identity info')}")
        print(f"  {dim(str(e))}")
        print()
        return 1

    print(divider())
    print()
    print(f"  {bold('APPLICATION IDENTITY')}")
    print()
    print(f"    {bold('ID:')}           {identity['identity_id']}")
    print(f"    {bold('Name:')}         {identity['name']}")
    print(f"    {bold('Team:')}         {identity['team']}")
    print(f"    {bold('Environment:')}  {identity['environment']}")
    print()
    print(f"  {bold('ALLOWED CONTEXTS')}")
    print()
    contexts = identity.get('allowed_contexts', [])
    if contexts:
        for ctx in contexts:
            print(f"    - {ctx}")
    else:
        print(dim("    No contexts configured"))
    print()
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
            print(f"  {error(f'Unknown option: {arg}')}")
            return 2

    if not token and not refresh_token and not server_url:
        # Interactive mode - show help
        print(compact_header("CONFIGURE"))
        print(divider())
        print()
        print(f"  {bold('ENVIRONMENT VARIABLES')}")
        print()
        print(dim("  Set these in your shell profile:"))
        print()
        print(f"    export CRYPTOSERVE_TOKEN=\"your-access-token\"")
        print(f"    export CRYPTOSERVE_REFRESH_TOKEN=\"...\"  {dim('# Optional')}")
        print(f"    export CRYPTOSERVE_SERVER_URL=\"http://localhost:8000\"")
        print()
        print(f"  {bold('COMMAND LINE')}")
        print()
        print(dim("  Or provide token directly:"))
        print()
        print(f"    cryptoserve configure --token <token>")
        print(f"    cryptoserve configure --server <url>")
        print()
        return 0

    print(compact_header("CONFIGURE"))

    # Set environment variables (for current session only)
    # User needs to set these permanently in their shell profile
    config_lines = []

    if token:
        os.environ["CRYPTOSERVE_TOKEN"] = token
        masked = token[:8] + "..." + token[-4:] if len(token) > 20 else token[:4] + "..."
        config_lines.append(('CRYPTOSERVE_TOKEN', masked, f'export CRYPTOSERVE_TOKEN="{token}"'))

    if refresh_token:
        os.environ["CRYPTOSERVE_REFRESH_TOKEN"] = refresh_token
        masked = refresh_token[:8] + "..." + refresh_token[-4:] if len(refresh_token) > 20 else refresh_token[:4] + "..."
        config_lines.append(('CRYPTOSERVE_REFRESH_TOKEN', masked, f'export CRYPTOSERVE_REFRESH_TOKEN="{refresh_token}"'))

    if server_url:
        os.environ["CRYPTOSERVE_SERVER_URL"] = server_url
        config_lines.append(('CRYPTOSERVE_SERVER_URL', server_url, f'export CRYPTOSERVE_SERVER_URL="{server_url}"'))

    # Reload config
    reload_config()

    print(f"  {success('Configuration updated for current session')}")
    print()

    print(f"  {bold('CONFIGURED VALUES')}")
    print()
    for name, value, _ in config_lines:
        print(f"    {bold(name + ':')}  {value}")
    print()

    print(divider())
    print()
    print(dim("  To make permanent, add to your shell profile (~/.bashrc, ~/.zshrc):"))
    print()
    for _, _, line in config_lines:
        print(f"    {line}")
    print()

    # Verify token if provided
    if token:
        print(divider())
        print()
        print(dim("  Verifying token..."))
        import requests as req
        try:
            from cryptoserve._identity import get_server_url
            resp = req.get(
                f"{get_server_url()}/health",
                headers={"Authorization": f"Bearer {token}"},
                timeout=10,
            )
            if resp.status_code == 200:
                print(f"  {success('Token valid')} {dim('Server reachable')}")
            else:
                print(f"  {warning(f'Server returned {resp.status_code}')}")
        except req.exceptions.ConnectionError:
            print(f"  {warning('Cannot reach server to verify token')}")
        except Exception as e:
            print(f"  {warning(f'Verification failed: {e}')}")
        print()

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

    print(compact_header("STATUS"))
    print(divider())

    # Configuration source
    source = get_config_source()
    print()
    print(f"  {bold('CONFIGURATION')}")
    print()
    print(f"    {bold('Source:')}  {source}")
    print(f"    {bold('Server:')}  {get_server_url()}")
    print()

    # Token status
    print(f"  {bold('TOKENS')}")
    print()

    token = get_token()
    if token:
        # Mask token
        if len(token) > 20:
            masked = token[:8] + "..." + token[-4:]
        else:
            masked = token[:4] + "..." if len(token) > 4 else "***"
        print(f"    {bold('Access Token:')}   {masked}")

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
                        print(f"    {bold('Expires:')}        {success(f'{hours}h {mins}m remaining')}")
                    else:
                        print(f"    {bold('Expires:')}        {error('EXPIRED')}")
                if "sub" in claims:
                    print(f"    {bold('Subject:')}        {claims['sub']}")
        except Exception:
            pass
    else:
        print(f"    {bold('Access Token:')}   {dim('Not configured')}")

    # Refresh token
    refresh = get_refresh_token()
    if refresh:
        if len(refresh) > 20:
            masked = refresh[:8] + "..." + refresh[-4:]
        else:
            masked = refresh[:4] + "..." if len(refresh) > 4 else "***"
        print(f"    {bold('Refresh Token:')}  {masked}")
    else:
        print(f"    {bold('Refresh Token:')}  {dim('Not configured')}")

    auto_refresh_status = success('Enabled') if AUTO_REFRESH_ENABLED else dim('Disabled')
    print(f"    {bold('Auto-Refresh:')}   {auto_refresh_status}")
    print()

    # Identity info
    print(f"  {bold('APPLICATION')}")
    print()
    name = IDENTITY.get('name', 'Not set')
    team = IDENTITY.get('team', 'Not set')
    env = IDENTITY.get('environment', 'Not set')
    print(f"    {bold('Name:')}         {name if name != 'Not set' else dim(name)}")
    print(f"    {bold('Team:')}         {team if team != 'Not set' else dim(team)}")
    print(f"    {bold('Environment:')} {env if env != 'Not set' else dim(env)}")

    contexts = IDENTITY.get("allowed_contexts", [])
    if contexts:
        print(f"    {bold('Contexts:')}     {', '.join(contexts)}")
    else:
        print(f"    {bold('Contexts:')}     {dim('None')}")
    print()

    # Overall status
    print(divider())
    print()

    if is_configured():
        # Try to verify via health endpoint
        import time
        import requests as req
        try:
            start = time.time()
            resp = req.get(f"{get_server_url()}/health", timeout=10)
            latency_ms = (time.time() - start) * 1000
            if resp.status_code == 200:
                print(f"  {success('SDK Connected')} {dim(f'(latency: {latency_ms:.0f}ms)')}")
            else:
                print(f"  {error(f'Server returned {resp.status_code}')}")
        except req.exceptions.ConnectionError:
            print(f"  {error('Cannot connect to server')}")
        except Exception as e:
            print(f"  {error(f'Connection Failed')} {dim(str(e))}")
    else:
        print(f"  {warning('SDK Not Configured')}")
        print()
        print(dim("  Run 'cryptoserve configure' for setup instructions"))

    print()
    return 0


def cmd_certs():
    """Certificate operations."""
    if len(sys.argv) < 3:
        print(compact_header("CERTIFICATES"))
        print(divider())
        print()
        print(f"  {bold('GENERATE-CSR')}  Create a Certificate Signing Request")
        print(dim("    cryptoserve certs generate-csr --cn <common-name> [options]"))
        print()
        print(f"    {dim('--org <org>')}         Organization name")
        print(f"    {dim('--country <code>')}    Country code (2 letters)")
        print(f"    {dim('--key-type ec|rsa')}   Key type (default: ec)")
        print(f"    {dim('--key-size <bits>')}   Key size (default: 256 for EC)")
        print(f"    {dim('--san <domain>')}      Subject Alternative Name (repeatable)")
        print(f"    {dim('--output <prefix>')}   Output file prefix")
        print()
        print(f"  {bold('SELF-SIGNED')}   Generate a self-signed certificate")
        print(dim("    cryptoserve certs self-signed --cn <common-name> [options]"))
        print()
        print(f"    {dim('--org <org>')}         Organization name")
        print(f"    {dim('--days <number>')}     Validity period (default: 365)")
        print(f"    {dim('--ca')}                Create as CA certificate")
        print(f"    {dim('--san <domain>')}      Subject Alternative Name")
        print(f"    {dim('--output <prefix>')}   Output file prefix")
        print()
        print(f"  {bold('PARSE')}         Parse and display certificate information")
        print(dim("    cryptoserve certs parse <cert.pem>"))
        print()
        print(f"  {bold('VERIFY')}        Verify a certificate")
        print(dim("    cryptoserve certs verify <cert.pem> [--issuer <ca.pem>]"))
        print()
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
        print(compact_header("CERTIFICATES"))
        print(f"  {error(f'Unknown subcommand: {subcommand}')}")
        print()
        print(dim("  Available: generate-csr, self-signed, parse, verify"))
        print()
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

    print(compact_header("GENERATE CSR"))

    if not cn:
        print(f"  {error('Missing required option: --cn (common name)')}")
        print()
        return 1

    print(dim("  Generating Certificate Signing Request..."))
    print()

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

        print(divider())
        print()

        if output_prefix:
            # Save to files
            with open(f"{output_prefix}.csr", "w") as f:
                f.write(result["csr_pem"])
            with open(f"{output_prefix}.key", "w") as f:
                f.write(result["private_key_pem"])
            os.chmod(f"{output_prefix}.key", 0o600)

            print(f"  {success('CSR generated successfully')}")
            print()
            print(f"  {bold('Files Created:')}")
            print(f"    CSR:         {output_prefix}.csr")
            print(f"    Private Key: {output_prefix}.key")
            print()
            print(f"  {warning('Keep the private key secure!')}")
        else:
            print(f"  {bold('CERTIFICATE SIGNING REQUEST')}")
            print()
            print(result["csr_pem"])
            print()
            print(f"  {bold('PRIVATE KEY')} {warning('(KEEP SECURE)')}")
            print()
            print(result["private_key_pem"])

        print()
        return 0

    except Exception as e:
        print(f"  {error(str(e))}")
        print()
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

    print(compact_header("SELF-SIGNED CERTIFICATE"))

    if not cn:
        print(f"  {error('Missing required option: --cn (common name)')}")
        print()
        return 1

    cert_type = "CA certificate" if is_ca else "certificate"
    print(dim(f"  Generating self-signed {cert_type}..."))
    print()

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

        print(divider())
        print()

        if output_prefix:
            with open(f"{output_prefix}.crt", "w") as f:
                f.write(result["certificate_pem"])
            with open(f"{output_prefix}.key", "w") as f:
                f.write(result["private_key_pem"])
            os.chmod(f"{output_prefix}.key", 0o600)

            print(f"  {success('Certificate generated successfully')}")
            print()
            print(f"  {bold('Files Created:')}")
            print(f"    Certificate: {output_prefix}.crt")
            print(f"    Private Key: {output_prefix}.key")
            print()
            print(f"  {bold('Details:')}")
            print(f"    Common Name: {cn}")
            print(f"    Validity:    {days} days")
            if is_ca:
                print(f"    Type:        CA Certificate")
            print()
            print(f"  {warning('Keep the private key secure!')}")
        else:
            print(f"  {bold('CERTIFICATE')}")
            print()
            print(result["certificate_pem"])
            print()
            print(f"  {bold('PRIVATE KEY')} {warning('(KEEP SECURE)')}")
            print()
            print(result["private_key_pem"])

        print()
        return 0

    except Exception as e:
        print(f"  {error(str(e))}")
        print()
        return 1


def _cmd_certs_parse():
    """Parse certificate."""
    from cryptoserve_client import CryptoClient
    from cryptoserve._identity import get_server_url, get_token

    print(compact_header("PARSE CERTIFICATE"))

    if len(sys.argv) < 4:
        print(f"  {error('Missing argument: certificate file')}")
        print()
        print(dim("  Usage: cryptoserve certs parse <cert.pem>"))
        print()
        return 1

    cert_file = sys.argv[3]

    try:
        with open(cert_file, "r") as f:
            cert_pem = f.read()
    except FileNotFoundError:
        print(f"  {error(f'File not found: {cert_file}')}")
        print()
        return 1

    print(dim(f"  Parsing {cert_file}..."))
    print()

    client = CryptoClient(server_url=get_server_url(), token=get_token())

    try:
        result = client.parse_certificate(cert_pem)

        print(divider())
        print()

        if "subject" in result:
            print(f"  {bold('SUBJECT')}")
            for key, value in result["subject"].items():
                print(f"    {key}: {value}")
            print()

        if "issuer" in result:
            print(f"  {bold('ISSUER')}")
            for key, value in result["issuer"].items():
                print(f"    {key}: {value}")
            print()

        if "validity" in result:
            print(f"  {bold('VALIDITY')}")
            print(f"    Not Before: {result['validity'].get('not_before', 'N/A')}")
            print(f"    Not After:  {result['validity'].get('not_after', 'N/A')}")
            print()

        if "key_info" in result:
            print(f"  {bold('PUBLIC KEY')}")
            print(f"    Algorithm: {result['key_info'].get('algorithm', 'N/A')}")
            print(f"    Size:      {result['key_info'].get('size', 'N/A')} bits")
            print()

        if "san" in result and result["san"]:
            print(f"  {bold('SUBJECT ALTERNATIVE NAMES')}")
            for san in result["san"]:
                print(f"    - {san}")
            print()

        print(f"  {bold('IDENTIFIERS')}")
        if "serial_number" in result:
            print(f"    Serial:      {result['serial_number']}")
        if "fingerprint" in result:
            print(f"    Fingerprint: {result['fingerprint']}")
        print()

        return 0

    except Exception as e:
        print(f"  {error(str(e))}")
        print()
        return 1


def _cmd_certs_verify():
    """Verify certificate."""
    from cryptoserve_client import CryptoClient
    from cryptoserve._identity import get_server_url, get_token

    print(compact_header("VERIFY CERTIFICATE"))

    if len(sys.argv) < 4:
        print(f"  {error('Missing argument: certificate file')}")
        print()
        print(dim("  Usage: cryptoserve certs verify <cert.pem> [--issuer <ca.pem>]"))
        print()
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
        print(f"  {error(f'File not found: {cert_file}')}")
        print()
        return 1

    issuer_pem = None
    if issuer_file:
        try:
            with open(issuer_file, "r") as f:
                issuer_pem = f.read()
        except FileNotFoundError:
            print(f"  {error(f'File not found: {issuer_file}')}")
            print()
            return 1

    print(dim(f"  Verifying {cert_file}..."))
    if issuer_file:
        print(dim(f"  Against issuer: {issuer_file}"))
    print()

    client = CryptoClient(server_url=get_server_url(), token=get_token())

    try:
        result = client.verify_certificate(
            certificate_pem=cert_pem,
            issuer_certificate_pem=issuer_pem,
            check_expiry=True,
        )

        print(divider())
        print()

        if result.get("valid"):
            print(f"  {success('Certificate is VALID')}")
        else:
            print(f"  {error('Certificate is INVALID')}")

        if result.get("errors"):
            print()
            print(f"  {bold('ERRORS')}")
            for err in result["errors"]:
                print(f"    {error(err)}")

        if result.get("warnings"):
            print()
            print(f"  {bold('WARNINGS')}")
            for warn in result["warnings"]:
                print(f"    {warning(warn)}")

        print()
        return 0 if result.get("valid") else 1

    except Exception as e:
        print(f"  {error(str(e))}")
        print()
        return 1


def cmd_promote():
    """Check promotion readiness or request promotion.

    Usage:
        cryptoserve promote <app-name>              # Check promotion readiness
        cryptoserve promote <app-name> --confirm    # Promote to production
        cryptoserve promote <app-name> --expedite   # Request expedited approval
        cryptoserve promote <app-name> --to staging # Promote to specific environment

    Requires login first: cryptoserve login
    """
    # Parse arguments - first positional arg is app name
    target_env = "production"
    expedite = False
    app_name = None
    check_only = True  # Default is to check readiness

    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]

        if arg in ["--to", "-t"] and i + 1 < len(sys.argv):
            target_env = sys.argv[i + 1]
            i += 2
        elif arg in ["--expedite", "-e"]:
            expedite = True
            check_only = False
            i += 1
        elif arg == "--confirm":
            check_only = False
            i += 1
        elif arg.startswith("-"):
            print(f"Unknown option: {arg}")
            return 1
        elif app_name is None:
            # First positional argument is the app name
            app_name = arg
            i += 1
        else:
            i += 1

    # Check if app name provided
    if not app_name:
        print(compact_header("PROMOTE"))
        print()
        print(f"  {bold('Usage:')} cryptoserve promote <app-name> [options]")
        print()
        print(f"  {bold('Examples:')}")
        print(dim("    cryptoserve promote my-backend-app              # Check readiness"))
        print(dim("    cryptoserve promote my-backend-app --confirm    # Promote if ready"))
        print(dim("    cryptoserve promote my-backend-app --expedite   # Request expedited"))
        print(dim("    cryptoserve promote my-backend-app --to staging # Target environment"))
        print()
        print(warning("Requires login first: cryptoserve login"))
        print()
        return 1

    # Check if logged in (use session-based auth, not SDK token)
    session_cookie = _get_session_cookie()
    server_url = _get_cli_server_url()

    if not session_cookie:
        print(compact_header("PROMOTE"))
        print()
        print(error("Not authenticated"))
        print()
        print(dim("  Please login first:"))
        print(dim("    cryptoserve login"))
        print()
        return 1

    import requests

    # Check promotion readiness
    print(compact_header("PROMOTE"))
    print(f"  {bold('Application:')} {app_name}")
    print(f"  {bold('Target:')} {target_env}")
    print()
    print(divider())

    # Use access_token cookie for authentication (matches backend expectation)
    cookies = {"access_token": session_cookie}

    try:
        # Look up app by name first
        response = requests.get(
            f"{server_url}/api/v1/applications",
            params={"name": app_name},
            cookies=cookies,
            timeout=30,
        )

        if response.status_code == 401:
            print()
            print(error("Session expired"))
            print(dim("  Please login again: cryptoserve login"))
            return 1

        response.raise_for_status()
        apps = response.json()

        # Find matching app
        app = None
        for a in apps:
            if a.get("name") == app_name or a.get("id") == app_name:
                app = a
                break

        if not app:
            print()
            print(error(f"Application not found: {app_name}"))
            if apps:
                print()
                print(dim("  Your applications:"))
                for a in apps[:5]:
                    print(dim(f"    • {a.get('name')} ({a.get('environment')})"))
            return 1

        app_id = app["id"]

        # Now get promotion readiness
        response = requests.get(
            f"{server_url}/api/v1/applications/{app_id}/promotion",
            params={"target": target_env},
            cookies=cookies,
            timeout=30,
        )

        if response.status_code == 404:
            print()
            print(error(f"Application not found: {app_name}"))
            return 1

        if response.status_code == 400:
            err_detail = response.json().get("detail", "Unknown error")
            print()
            print(error(err_detail))
            return 1

        response.raise_for_status()
        data = response.json()

    except requests.exceptions.ConnectionError:
        print()
        print(error(f"Cannot connect to server at {server_url}"))
        return 1
    except requests.exceptions.RequestException as e:
        print()
        print(error(str(e)))
        return 1

    # Display readiness for each context
    print()
    print(f"  {bold('CONTEXT READINESS')}")
    print()

    for ctx in data.get("contexts", []):
        context_name = ctx["context"]
        tier = ctx["tier_display"]

        # Context header with tier badge
        tier_color = Style.SUCCESS if "Low" in tier else (Style.WARNING if "Medium" in tier else Style.ERROR) if STYLED else ""
        reset = Style.RESET if STYLED else ""
        print(f"  {bold(context_name)} {dim(f'({tier})')}")

        # Operations
        ops_current = ctx["current_operations"]
        ops_required = ctx["required_operations"]
        ops_met = ctx["operations_met"]
        if ops_met:
            print(f"    {success(f'Operations: {ops_current}/{ops_required}')}")
        else:
            print(f"    {error(f'Operations: {ops_current}/{ops_required}')} {dim(f'(need {ops_required - ops_current} more)')}")

        # Time in dev
        hours_current = ctx["current_hours"]
        hours_required = ctx["required_hours"]
        hours_met = ctx["hours_met"]
        if hours_met:
            print(f"    {success(f'Time in dev: {hours_current:.0f}h/{hours_required}h')}")
        else:
            print(f"    {error(f'Time in dev: {hours_current:.0f}h/{hours_required}h')} {dim(f'(need {hours_required - hours_current:.0f}h more)')}")

        # Unique days
        days_current = ctx["current_unique_days"]
        days_required = ctx["required_days"]
        days_met = ctx["days_met"]
        if days_met:
            print(f"    {success(f'Unique days: {days_current}/{days_required}')}")
        else:
            print(f"    {error(f'Unique days: {days_current}/{days_required}')} {dim(f'(need {days_required - days_current} more)')}")

        # Admin approval
        if ctx["requires_approval"]:
            print(f"    {warning('Requires admin approval (Tier 3)')}")

        print()

    # Summary
    is_ready = data.get("is_ready", False)
    requires_approval = data.get("requires_approval", False)
    ready_count = data.get("ready_count", 0)
    total_count = data.get("total_count", 0)

    print(divider())
    print()
    print(f"  {bold('SUMMARY')}")
    print(f"  Ready: {ready_count}/{total_count} contexts")
    print()

    if is_ready:
        if requires_approval:
            print(f"  {success('Thresholds met')}")
            print(f"  {warning('Admin approval required for Tier 3 contexts')}")
        else:
            print(f"  {success('Ready for promotion!')}")

        if check_only:
            print()
            print(dim("  To promote, run:"))
            print(f"    cryptoserve promote {app_name} --confirm")
        else:
            # Proceed with promotion
            return _do_promotion(server_url, cookies, app_id, target_env)

    else:
        # Not ready
        print(f"  {error('Not ready for promotion')}")

        estimated = data.get("estimated_ready_at")
        if estimated:
            from datetime import datetime
            try:
                est_dt = datetime.fromisoformat(estimated.replace("Z", "+00:00"))
                est_str = est_dt.strftime("%a, %b %d at %I:%M %p")
                print()
                print(f"  {info(f'Estimated ready: {est_str}')}")
            except Exception:
                pass

        print()
        print(dim("  Options:"))
        print(dim("    [1] Continue developing, promote when thresholds met"))
        print(dim("    [2] Request expedited approval (requires justification)"))

        if expedite:
            return _request_expedited(server_url, cookies, app_id)
        elif not check_only:
            print()
            print(warning("Thresholds not met. Use --expedite to request expedited approval."))
            return 1

    print()
    return 0


def _do_promotion(server_url: str, cookies: dict, app_id: str, target_env: str) -> int:
    """Execute the actual promotion."""
    import requests

    print()
    print(dim(f"  Promoting to {target_env}..."))

    try:
        response = requests.post(
            f"{server_url}/api/v1/applications/{app_id}/promotion",
            json={"target_environment": target_env},
            cookies=cookies,
            timeout=30,
        )

        if response.status_code == 400:
            err_msg = response.json().get("detail", "Promotion failed")
            print()
            print(f"  {error(err_msg)}")
            return 1

        response.raise_for_status()
        data = response.json()

        print()
        print(f"  {success(data.get('message', 'Promotion successful!'))}")
        print()
        return 0

    except requests.exceptions.RequestException as e:
        print()
        print(f"  {error(str(e))}")
        return 1


def _request_expedited(server_url: str, cookies: dict, app_id: str) -> int:
    """Request expedited promotion approval."""
    import requests

    print()
    print(divider())
    print()
    print(f"  {bold('EXPEDITED PROMOTION REQUEST')}")
    print()

    # Get priority
    print(f"  {bold('Priority:')}")
    print(dim("    [1] Critical - Production down, security incident"))
    print(dim("    [2] High - Customer-impacting, need today"))
    print(dim("    [3] Normal - Business need, flexible timing"))

    try:
        choice = input("\n  Select priority [1-3]: ").strip()
        priority_map = {"1": "critical", "2": "high", "3": "normal"}
        priority = priority_map.get(choice, "normal")
    except (EOFError, KeyboardInterrupt):
        print()
        print(dim("  Cancelled."))
        return 1

    # Get justification
    print()
    print(f"  {bold('Justification')} {dim('(required):')}")
    try:
        justification = input("  > ").strip()
        if not justification or len(justification) < 10:
            print()
            print(f"  {error('Justification must be at least 10 characters')}")
            return 1
    except (EOFError, KeyboardInterrupt):
        print()
        print(dim("  Cancelled."))
        return 1

    # Submit request
    print()
    print(dim("  Submitting request..."))

    try:
        response = requests.post(
            f"{server_url}/api/v1/applications/{app_id}/promotion/expedite",
            json={
                "priority": priority,
                "justification": justification,
            },
            cookies=cookies,
            timeout=30,
        )

        if response.status_code == 400:
            err_msg = response.json().get("detail", "Request failed")
            print()
            print(f"  {error(err_msg)}")
            return 1

        response.raise_for_status()
        data = response.json()

        print()
        print(divider())
        print()
        print(f"  {success(data.get('message', 'Expedited request submitted'))}")

        if data.get("thresholds_bypassed"):
            print()
            print(f"  {bold('Thresholds bypassed:')}")
            for t in data["thresholds_bypassed"]:
                print(dim(f"    - {t}"))

        if data.get("next_steps"):
            print()
            print(f"  {bold('Next steps:')}")
            for step in data["next_steps"]:
                print(dim(f"    - {step}"))

        request_id = data.get("request_id")
        if request_id:
            print()
            print(f"  {bold('Request ID:')} {request_id}")

        print()
        return 0

    except requests.exceptions.RequestException as e:
        print()
        print(f"  {error(str(e))}")
        return 1


def cmd_wizard():
    """Interactive context selection wizard."""
    print(compact_header("CONTEXT WIZARD"))
    print(dim("  Answer a few questions to find the right crypto context."))
    print()

    # Step 1: Data Type
    print(divider())
    print()
    print(f"  {bold('STEP 1:')} What type of data are you protecting?")
    print()
    data_types = [
        ("pii", "Personal Information (names, emails, addresses)"),
        ("financial", "Financial Data (payment cards, bank accounts)"),
        ("health", "Health Records (medical data, PHI)"),
        ("auth", "Authentication (passwords, tokens, API keys)"),
        ("business", "Business Data (contracts, strategies)"),
        ("general", "General Sensitive Data"),
    ]

    for i, (key, desc) in enumerate(data_types, 1):
        print(f"    {bold(str(i))}. {desc}")

    while True:
        try:
            choice = input("\n  Select [1-6]: ").strip()
            data_type = data_types[int(choice) - 1][0]
            break
        except (ValueError, IndexError):
            print(f"  {warning('Please enter a number 1-6')}")

    # Step 2: Compliance
    print()
    print(divider())
    print()
    print(f"  {bold('STEP 2:')} Which compliance frameworks apply?")
    print()
    frameworks = [
        ("none", "None / Not Sure"),
        ("soc2", "SOC 2"),
        ("hipaa", "HIPAA (Healthcare)"),
        ("pci", "PCI-DSS (Payment Cards)"),
        ("gdpr", "GDPR (EU Data Protection)"),
        ("multiple", "Multiple Frameworks"),
    ]

    for i, (key, desc) in enumerate(frameworks, 1):
        print(f"    {bold(str(i))}. {desc}")

    while True:
        try:
            choice = input("\n  Select [1-6]: ").strip()
            compliance = frameworks[int(choice) - 1][0]
            break
        except (ValueError, IndexError):
            print(f"  {warning('Please enter a number 1-6')}")

    # Step 3: Threat Level
    print()
    print(divider())
    print()
    print(f"  {bold('STEP 3:')} What is your threat model?")
    print()
    threats = [
        ("standard", "Standard Protection (opportunistic attackers)"),
        ("elevated", "Elevated Security (organized threats)"),
        ("maximum", "Maximum Security (nation-state level)"),
        ("quantum", "Quantum-Ready (future-proof encryption)"),
    ]

    for i, (key, desc) in enumerate(threats, 1):
        print(f"    {bold(str(i))}. {desc}")

    while True:
        try:
            choice = input("\n  Select [1-4]: ").strip()
            threat = threats[int(choice) - 1][0]
            break
        except (ValueError, IndexError):
            print(f"  {warning('Please enter a number 1-4')}")

    # Step 4: Performance
    print()
    print(divider())
    print()
    print(f"  {bold('STEP 4:')} What are your performance requirements?")
    print()
    perf_options = [
        ("realtime", "Real-time (<10ms latency required)"),
        ("interactive", "Interactive (<100ms acceptable)"),
        ("batch", "Batch Processing (latency not critical)"),
    ]

    for i, (key, desc) in enumerate(perf_options, 1):
        print(f"    {bold(str(i))}. {desc}")

    while True:
        try:
            choice = input("\n  Select [1-3]: ").strip()
            perf = perf_options[int(choice) - 1][0]
            break
        except (ValueError, IndexError):
            print(f"  {warning('Please enter a number 1-3')}")

    # Generate recommendation
    print()
    print(divider())
    print()
    print(f"  {bold('RECOMMENDATION')}")
    print()

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

    print(f"    {bold('Context:')}      {context_name}")
    print(f"    {bold('Algorithm:')}    {algorithm}")

    q_ready = success("Yes") if quantum_ready else dim("No")
    print(f"    {bold('Quantum Safe:')} {q_ready}")

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
        print(f"    {bold('Compliance:')}  {', '.join(compliance_tags)}")

    print()

    # Show code snippet
    print(divider())
    print()
    print(f"  {bold('CODE EXAMPLE')}")
    print()
    print(dim(f'''    from cryptoserve import crypto

    # Encrypt sensitive data
    ciphertext = crypto.encrypt(
        b"sensitive data here",
        context="{context_name}"
    )

    # Decrypt when needed
    plaintext = crypto.decrypt(ciphertext, context="{context_name}")'''))

    print()
    print(divider())
    print()
    print(f"  {bold('NEXT STEPS')}")
    print()
    print(f"    1. Request access to '{context_name}' context from your admin")
    print("    2. Or create a new context in the dashboard")
    print("    3. Use the code snippet above in your application")
    print()

    # Offer to open dashboard
    try:
        open_dash = input("  Open dashboard to create this context? [y/N]: ").strip().lower()
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
                print(f"  {success('Opening dashboard...')}")
            except Exception:
                print(f"  {warning('Could not open browser. Visit your CryptoServe dashboard manually.')}")
    except (EOFError, KeyboardInterrupt):
        print()

    print()
    return 0


def cmd_contexts():
    """List and search encryption contexts.

    Usage:
        cryptoserve contexts                   # List all available contexts
        cryptoserve contexts "email"           # Search for contexts matching "email"
        cryptoserve contexts pii               # Search for PII-related contexts
        cryptoserve contexts --example user-pii   # Show usage example for specific context
    """
    import requests

    # Parse arguments
    query = ""
    show_example_for = None

    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]

        if arg in ["--example", "-e"] and i + 1 < len(sys.argv):
            show_example_for = sys.argv[i + 1]
            i += 2
        elif not arg.startswith("-"):
            query = arg
            i += 1
        else:
            i += 1

    # Get SDK token
    from cryptoserve._identity import get_token, get_server_url, is_configured

    if not is_configured():
        print(compact_header("CONTEXTS"))
        print()
        print(error("SDK not configured"))
        print()
        print(dim("  Configure with:"))
        print(dim("    cryptoserve configure --token <your-token>"))
        print()
        return 1

    token = get_token()
    server_url = get_server_url()

    print(compact_header("CONTEXTS"))

    if show_example_for:
        # Show example for specific context
        print(dim(f"  Loading context: {show_example_for}"))
        print()

        try:
            response = requests.get(
                f"{server_url}/sdk/contexts/{show_example_for}",
                headers={"Authorization": f"Bearer {token}"},
                timeout=10,
            )

            if response.status_code == 403:
                print(error(f"Not authorized for context '{show_example_for}'"))
                return 1
            elif response.status_code == 404:
                print(error(f"Context '{show_example_for}' not found"))
                return 1

            response.raise_for_status()
            ctx = response.json()

            print(divider())
            print()
            print(f"  {bold(ctx['name'])}")
            if ctx.get('display_name'):
                print(f"  {dim(ctx['display_name'])}")
            print()

            if ctx.get('description'):
                print(f"  {bold('Description:')}")
                print(f"    {ctx['description']}")
                print()

            print(f"  {bold('Algorithm:')}     {ctx['algorithm']}")
            print(f"  {bold('Speed:')}         {ctx.get('speed', 'unknown')}")
            print(f"  {bold('Overhead:')}      {ctx.get('overhead_bytes', 0)} bytes")

            q_safe = success("Yes") if ctx.get('quantum_safe') else dim("No")
            print(f"  {bold('Quantum Safe:')} {q_safe}")

            if ctx.get('compliance'):
                print(f"  {bold('Compliance:')}   {', '.join(ctx['compliance'])}")

            if ctx.get('data_examples'):
                print(f"  {bold('Data Examples:')} {', '.join(ctx['data_examples'])}")

            print()
            print(divider())
            print()
            print(f"  {bold('QUICK START')}")
            print()
            print(dim(f'''    from cryptoserve import crypto

    # Encrypt
    ciphertext = crypto.encrypt(
        b"your sensitive data",
        context="{ctx['name']}"
    )

    # Decrypt
    plaintext = crypto.decrypt(ciphertext, context="{ctx['name']}")'''))
            print()

            return 0

        except requests.exceptions.ConnectionError:
            print(error(f"Cannot connect to server at {server_url}"))
            return 1
        except requests.exceptions.RequestException as e:
            print(error(str(e)))
            return 1

    # Search/list contexts
    if query:
        print(dim(f"  Searching for: {query}"))
    else:
        print(dim("  Loading available contexts..."))
    print()

    try:
        response = requests.get(
            f"{server_url}/sdk/contexts/search",
            params={"q": query} if query else {},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )

        if response.status_code == 401:
            print(error("Token expired or invalid"))
            print(dim("  Run 'cryptoserve configure' to update your token"))
            return 1

        response.raise_for_status()
        data = response.json()

        contexts = data.get("contexts", [])
        total = data.get("total", len(contexts))

        print(divider())
        print()

        if not contexts:
            if query:
                msg = f'No contexts found matching "{query}"'
                print(f"  {warning(msg)}")
                print()
                print(dim("  Try a different search term, or run without a query:"))
                print(dim("    cryptoserve contexts"))
            else:
                print(f"  {warning('No contexts available')}")
                print()
                print(dim("  Contact your admin to request access to contexts."))
            print()
            return 0

        print(f"  {bold(f'You have access to {total} context(s):')}")
        print()

        for ctx in contexts:
            # Context box
            q_badge = f" {success('QS')}" if ctx.get('quantum_safe') else ""
            print(f"  ┌{'─' * 58}┐")
            print(f"  │  {bold(ctx['name'])}{q_badge:<{50 - len(ctx['name'])}}│")

            # Description (truncated)
            desc = ctx.get('description', ctx.get('display_name', ''))
            if len(desc) > 52:
                desc = desc[:49] + "..."
            print(f"  │  {dim(desc):<{56}}│")

            # Algorithm and compliance
            algo = ctx.get('algorithm', 'Unknown')
            compliance = ', '.join(ctx.get('compliance', []))[:20] or 'None'
            algo_line = f"Algorithm: {algo}"
            comp_line = f"Compliance: {compliance}"
            print(f"  │  {algo_line:<28}{comp_line:<28}│")

            # Match info (if searching)
            if ctx.get('matches'):
                matches_str = f"Matched: {', '.join(ctx['matches'][:2])}"
                if len(matches_str) > 52:
                    matches_str = matches_str[:49] + "..."
                print(f"  │  {dim(matches_str):<{56}}│")

            print(f"  └{'─' * 58}┘")
            print()

        # Footer with usage hint
        print(divider())
        print()
        print(f"  {bold('QUICK START:')}")
        first_ctx = contexts[0]['name'] if contexts else 'user-pii'
        print(f"    encrypted = crypto.encrypt(data, context=\"{first_ctx}\")")
        print()
        print(dim("  For details on a specific context:"))
        print(dim(f"    cryptoserve contexts --example {first_ctx}"))
        print()

        return 0

    except requests.exceptions.ConnectionError:
        print(error(f"Cannot connect to server at {server_url}"))
        return 1
    except requests.exceptions.RequestException as e:
        print(error(str(e)))
        return 1


def cmd_scan():
    """Scan for crypto libraries."""
    from cryptoserve import init

    print(compact_header("SCAN"))
    print(dim("  Scanning for cryptographic libraries..."))
    print()

    result = init(report_to_platform=False, async_reporting=False)

    if not result.success:
        print(f"  {error(f'Scan failed: {result.error}')}")
        return 1

    print(divider())
    print()
    print(f"  {bold('DETECTED LIBRARIES')} {dim(f'({len(result.libraries)} found)')}")
    print()

    for lib in result.libraries:
        # Determine status badge
        if lib.get("is_deprecated"):
            status_badge = f" {error('DEPRECATED')}"
        elif lib.get("quantum_risk") in ["high", "critical"]:
            status_badge = f" {warning('QUANTUM RISK')}"
        else:
            status_badge = ""

        # Library name with status
        print(f"    {bold(lib['name'])}{status_badge}")

        # Details
        if lib.get("version"):
            print(f"      {dim('Version:')}      {lib['version']}")
        print(f"      {dim('Category:')}     {lib['category']}")

        # Quantum risk with color
        q_risk = lib.get('quantum_risk', 'unknown')
        if q_risk in ['high', 'critical']:
            q_display = error(q_risk)
        elif q_risk == 'medium':
            q_display = warning(q_risk)
        else:
            q_display = success(q_risk) if q_risk in ['none', 'low'] else q_risk
        print(f"      {dim('Quantum Risk:')} {q_display}")

        # Algorithms
        algorithms = lib.get('algorithms', [])
        if algorithms:
            print(f"      {dim('Algorithms:')}   {', '.join(algorithms)}")
        print()

    # Summary section
    vulnerable = len(result.quantum_vulnerable)
    deprecated = len(result.deprecated)
    total = len(result.libraries)

    print(divider())
    print()
    print(f"  {bold('SUMMARY')}")
    print()
    print(f"    {bold('Total Libraries:')}     {total}")

    if deprecated > 0:
        print(f"    {bold('Deprecated:')}          {error(str(deprecated))}")
    else:
        print(f"    {bold('Deprecated:')}          {success('0')}")

    if vulnerable > 0:
        print(f"    {bold('Quantum Vulnerable:')}  {warning(str(vulnerable))}")
    else:
        print(f"    {bold('Quantum Vulnerable:')}  {success('0')}")

    print()

    # Overall status
    if deprecated == 0 and vulnerable == 0:
        print(f"  {success('No security issues detected')}")
    elif deprecated > 0 or vulnerable > 0:
        print(f"  {warning('Review recommended for flagged libraries')}")

    print()
    return 0


def cmd_cbom():
    """Generate CBOM and optionally upload to platform."""
    import os
    from cryptoserve import export_cbom

    # Parse arguments
    format_arg = "json"
    output_file = None
    local_only = False
    upload = True  # Default: upload to platform
    scan_path = None
    scan_name = None

    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]

        if arg in ["--format", "-f"] and i + 1 < len(sys.argv):
            format_arg = sys.argv[i + 1]
            i += 2
        elif arg in ["--output", "-o"] and i + 1 < len(sys.argv):
            output_file = sys.argv[i + 1]
            i += 2
        elif arg in ["--name", "-n"] and i + 1 < len(sys.argv):
            scan_name = sys.argv[i + 1]
            i += 2
        elif arg in ["--local", "--no-upload"]:
            local_only = True
            upload = False
            i += 1
        elif arg == "--upload":
            upload = True
            local_only = False
            i += 1
        elif arg in ["json", "cyclonedx", "spdx"]:
            format_arg = arg
            i += 1
        elif not arg.startswith("-") and scan_path is None:
            # Positional argument is the scan path
            scan_path = os.path.abspath(arg)
            i += 1
        else:
            i += 1

    # Default to current directory
    if scan_path is None:
        scan_path = os.getcwd()

    # Change to scan path for library detection
    original_cwd = os.getcwd()
    try:
        os.chdir(scan_path)
    except Exception:
        pass

    print(compact_header("CBOM"))
    print(dim(f"  Scanning: {scan_path}"))
    print(dim(f"  Generating Cryptographic Bill of Materials ({format_arg})..."))
    print()

    try:
        result = export_cbom(format=format_arg)

        if output_file:
            result.save(output_file)
            print(divider())
            print()
            print(f"  {success(f'CBOM saved to {output_file}')}")
        else:
            print(divider())
            print()
            print(result.to_json())

        print()
        print(divider())
        print()
        print(f"  {bold('SUMMARY')}")
        print()

        # Score with color
        score = result.score
        if score >= 80:
            score_display = success(f"{score:.0f}%")
        elif score >= 50:
            score_display = warning(f"{score:.0f}%")
        else:
            score_display = error(f"{score:.0f}%")

        print(f"    {bold('Quantum Readiness:')} {score_display}")

        # Risk level with color
        risk = result.risk_level.lower()
        if risk in ["low", "none"]:
            risk_display = success(result.risk_level)
        elif risk == "medium":
            risk_display = warning(result.risk_level)
        else:
            risk_display = error(result.risk_level)

        print(f"    {bold('Risk Level:')}        {risk_display}")

        # Upload to platform if not local-only
        if upload and not local_only:
            print()
            print(dim("  Uploading to CryptoServe platform..."))
            upload_result = _upload_cbom(result, scan_path=scan_path, scan_name=scan_name)
            if upload_result:
                print(f"  {success('CBOM uploaded to platform')}")
                print(dim("    View in dashboard: Tools > CBOM Reports"))
            else:
                print(f"  {warning('Upload skipped (not authenticated or server unavailable)')}")
                print(dim("    Run 'cryptoserve login' to enable platform sync"))

        print()
        return 0

    except Exception as e:
        print(f"  {error(str(e))}")
        print()
        return 1
    finally:
        # Restore original directory
        os.chdir(original_cwd)


def _get_git_info() -> dict:
    """Get git repository information if available."""
    import subprocess
    import os

    git_info = {}
    try:
        # Check if we're in a git repo
        result = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            return git_info

        # Get commit hash
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            git_info["git_commit"] = result.stdout.strip()

        # Get branch name
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            git_info["git_branch"] = result.stdout.strip()

        # Get remote URL
        result = subprocess.run(
            ["git", "config", "--get", "remote.origin.url"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            git_info["git_repo"] = result.stdout.strip()

    except Exception:
        pass

    return git_info


def _upload_cbom(cbom_result, scan_path: str = None, scan_name: str = None) -> bool:
    """Upload CBOM to CryptoServe platform."""
    import requests
    import os

    # Try SDK token first, then session cookie
    from cryptoserve._identity import get_token, get_server_url, is_configured

    token = get_token()
    server_url = get_server_url()

    # Get git info
    git_info = _get_git_info()

    # Build payload
    payload = {
        "format": "json",
        "content": cbom_result.to_dict(),
        "score": cbom_result.score,
        "risk_level": cbom_result.risk_level,
        "scan_path": scan_path or os.getcwd(),
        "scan_name": scan_name or os.path.basename(scan_path or os.getcwd()),
        **git_info,
    }

    # If SDK not configured, try session-based auth
    if not token or not is_configured():
        session_cookie = _get_session_cookie()
        cli_server_url = _get_cli_server_url()
        if not session_cookie:
            return False
        server_url = cli_server_url

        try:
            response = requests.post(
                f"{server_url}/api/v1/cbom",
                json=payload,
                cookies={"access_token": session_cookie},
                timeout=30,
            )
            return response.status_code in [200, 201]
        except Exception:
            return False
    else:
        # Use SDK token
        try:
            response = requests.post(
                f"{server_url}/api/v1/cbom",
                json=payload,
                headers={"Authorization": f"Bearer {token}"},
                timeout=30,
            )
            return response.status_code in [200, 201]
        except Exception:
            return False


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

    print(compact_header("PQC ANALYSIS"))
    print(dim(f"  Analyzing post-quantum cryptography readiness..."))
    print(dim(f"  Profile: {data_profile}"))
    print()

    try:
        result = get_pqc_recommendations(data_profile=data_profile)

        print(divider())
        print()

        # Urgency with color
        urgency = result.urgency.lower()
        if urgency == "critical":
            urgency_display = error("CRITICAL")
        elif urgency == "high":
            urgency_display = error("HIGH")
        elif urgency == "medium":
            urgency_display = warning("MEDIUM")
        else:
            urgency_display = success(urgency.upper())

        # Score with color
        score = result.score
        if score >= 80:
            score_display = success(f"{score:.0f}%")
        elif score >= 50:
            score_display = warning(f"{score:.0f}%")
        else:
            score_display = error(f"{score:.0f}%")

        print(f"  {bold('QUANTUM READINESS')}")
        print()
        print(f"    Migration Urgency: {urgency_display}")
        print(f"    Readiness Score:   {score_display}")
        print()

        # SNDL warning
        if result.sndl_vulnerable:
            print(f"  {error('SNDL RISK')}")
            print(f"    Your data may be vulnerable to")
            print(f"    'Store Now, Decrypt Later' attacks!")
            print()

        # Key findings
        if result.key_findings:
            print(f"  {bold('KEY FINDINGS')}")
            print()
            for finding in result.key_findings:
                print(f"    - {finding}")
            print()

        # Recommendations
        if result.kem_recommendations:
            print(f"  {bold('KEM (KEY EXCHANGE) RECOMMENDATIONS')}")
            print()
            for rec in result.kem_recommendations:
                print(f"    {dim(rec['current_algorithm'])} -> {bold(rec['recommended_algorithm'])}")
                print(f"      Standard:  {rec['fips_standard']}")
                print(f"      Rationale: {rec['rationale']}")
                print()

        if result.signature_recommendations:
            print(f"  {bold('SIGNATURE RECOMMENDATIONS')}")
            print()
            for rec in result.signature_recommendations:
                print(f"    {dim(rec['current_algorithm'])} -> {bold(rec['recommended_algorithm'])}")
                print(f"      Standard: {rec['fips_standard']}")
                print()

        # Next steps
        if result.next_steps:
            print(divider())
            print()
            print(f"  {bold('NEXT STEPS')}")
            print()
            for idx, step in enumerate(result.next_steps[:5], 1):
                print(f"    {idx}. {step}")
            print()

        return 0

    except Exception as e:
        print(f"  {error(str(e))}")
        print()
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
            print(compact_header("GATE"))
            print(f"  {error(f'Unknown option: {arg}')}")
            print()
            return 2
        else:
            paths.append(arg)
            i += 1

    # Default to current directory
    if not paths and not staged_only:
        paths = ["."]

    # Only show header for text format
    if output_format == "text":
        print(compact_header("GATE"))
        print(dim(f"  Policy: {policy}"))
        if staged_only:
            print(dim("  Scanning git staged files only"))
        else:
            print(dim(f"  Paths: {', '.join(paths)}"))
        print()

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
            print(divider())
            print()
            print(format_text_output(result))
            print()
            # Add summary with styled status
            if result.exit_code == 0:
                print(f"  {success('Gate check passed')}")
            else:
                print(f"  {error('Gate check failed')}")
            print()

        return result.exit_code

    except ValueError as e:
        if output_format == "text":
            print(f"  {error(f'Configuration error: {e}')}")
            print()
        else:
            print(f"Configuration error: {e}")
        return 2
    except Exception as e:
        if output_format == "text":
            print(f"  {error(f'Gate check failed: {e}')}")
            print()
        else:
            print(f"Gate check failed: {e}")
        return 2


# =============================================================================
# OFFLINE TOOLS (no server required)
# =============================================================================

def cmd_encrypt():
    """Encrypt a string or file with a password."""
    import base64
    from cryptoserve_core import encrypt_string, encrypt_file

    # Parse arguments
    text = None
    password = None
    file_path = None
    output_path = None

    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ["--password", "-p"] and i + 1 < len(sys.argv):
            password = sys.argv[i + 1]
            i += 2
        elif arg in ["--file", "-f"] and i + 1 < len(sys.argv):
            file_path = sys.argv[i + 1]
            i += 2
        elif arg in ["--output", "-o"] and i + 1 < len(sys.argv):
            output_path = sys.argv[i + 1]
            i += 2
        elif not arg.startswith("-") and text is None:
            text = arg
            i += 1
        else:
            i += 1

    if not password:
        print(error("Missing required option: --password"))
        print(dim("  Usage: cryptoserve encrypt \"text\" --password <password>"))
        print(dim("         cryptoserve encrypt --file <path> --output <path> --password <password>"))
        return 1

    if file_path:
        # File mode
        if not output_path:
            output_path = file_path + ".enc"
        try:
            encrypt_file(file_path, output_path, password)
            print(success(f"Encrypted: {file_path} -> {output_path}"))
            return 0
        except Exception as e:
            print(error(str(e)))
            return 1
    elif text is not None:
        # String mode
        try:
            result = encrypt_string(text, password)
            print(result)
            return 0
        except Exception as e:
            print(error(str(e)))
            return 1
    else:
        print(error("Provide text to encrypt or use --file"))
        print(dim("  Usage: cryptoserve encrypt \"text\" --password <password>"))
        return 1


def cmd_decrypt():
    """Decrypt a string or file with a password."""
    from cryptoserve_core import decrypt_string, decrypt_file

    # Parse arguments
    text = None
    password = None
    file_path = None
    output_path = None

    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ["--password", "-p"] and i + 1 < len(sys.argv):
            password = sys.argv[i + 1]
            i += 2
        elif arg in ["--file", "-f"] and i + 1 < len(sys.argv):
            file_path = sys.argv[i + 1]
            i += 2
        elif arg in ["--output", "-o"] and i + 1 < len(sys.argv):
            output_path = sys.argv[i + 1]
            i += 2
        elif not arg.startswith("-") and text is None:
            text = arg
            i += 1
        else:
            i += 1

    if not password:
        print(error("Missing required option: --password"))
        print(dim("  Usage: cryptoserve decrypt \"<base64>\" --password <password>"))
        print(dim("         cryptoserve decrypt --file <path> --output <path> --password <password>"))
        return 1

    if file_path:
        # File mode
        if not output_path:
            print(error("Missing required option: --output for file decryption"))
            return 1
        try:
            decrypt_file(file_path, output_path, password)
            print(success(f"Decrypted: {file_path} -> {output_path}"))
            return 0
        except Exception as e:
            print(error(str(e)))
            return 1
    elif text is not None:
        # String mode
        try:
            result = decrypt_string(text, password)
            print(result)
            return 0
        except Exception as e:
            print(error(str(e)))
            return 1
    else:
        print(error("Provide base64 ciphertext to decrypt or use --file"))
        print(dim("  Usage: cryptoserve decrypt \"<base64>\" --password <password>"))
        return 1


def cmd_hash_password():
    """Hash a password."""
    import getpass
    from cryptoserve_core import hash_password

    # Parse arguments
    password = None
    algorithm = "scrypt"

    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ["--algo", "--algorithm", "-a"] and i + 1 < len(sys.argv):
            algorithm = sys.argv[i + 1]
            i += 2
        elif not arg.startswith("-") and password is None:
            password = arg
            i += 1
        else:
            i += 1

    if password is None:
        try:
            password = getpass.getpass("Password: ")
        except (EOFError, KeyboardInterrupt):
            print()
            return 1

    if not password:
        print(error("Password cannot be empty"))
        return 1

    try:
        result = hash_password(password, algorithm=algorithm)
        print(result)
        return 0
    except ValueError as e:
        print(error(str(e)))
        return 1
    except Exception as e:
        print(error(str(e)))
        return 1


def cmd_token():
    """Create a JWT token."""
    from cryptoserve_core import create_token

    # Parse arguments
    key = None
    payload_str = None
    expires = 3600

    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ["--key", "-k"] and i + 1 < len(sys.argv):
            key = sys.argv[i + 1]
            i += 2
        elif arg in ["--payload"] and i + 1 < len(sys.argv):
            payload_str = sys.argv[i + 1]
            i += 2
        elif arg in ["--expires", "--exp", "-e"] and i + 1 < len(sys.argv):
            expires = int(sys.argv[i + 1])
            i += 2
        else:
            i += 1

    if not key:
        print(error("Missing required option: --key"))
        print(dim("  Usage: cryptoserve token --key <secret> [--payload '{...}'] [--expires N]"))
        return 1

    key_bytes = key.encode("utf-8")
    if len(key_bytes) < 16:
        print(error("Key must be at least 16 bytes"))
        return 1

    payload = {}
    if payload_str:
        try:
            payload = json.loads(payload_str)
        except json.JSONDecodeError as e:
            print(error(f"Invalid JSON payload: {e}"))
            return 1

    try:
        token = create_token(payload, key=key_bytes, expires_in=expires)
        print(token)
        return 0
    except Exception as e:
        print(error(str(e)))
        return 1


def cmd_help():
    """Show help."""
    print(compact_header("HELP"))
    print(dim("  Usage: cryptoserve <command> [options]"))
    print()
    print(divider())
    print()
    print(f"  {bold('QUICK START')}")
    print()
    print(dim("    1. Login once:"))
    print(f"       cryptoserve login")
    print()
    print(dim("    2. Use in your code:"))
    print(dim('       from cryptoserve import CryptoServe'))
    print(dim('       crypto = CryptoServe(app_name="my-app")'))
    print(dim('       # App auto-registers on first use!'))
    print()
    print(divider())
    print()
    print(f"  {bold('AUTHENTICATION')}")
    print()
    print(f"    {bold('login')}      Login to CryptoServe (opens browser)")
    print(dim("               --server <url>  Server URL"))
    print(dim("               --dev           Force dev mode login"))
    print(dim("               --cookie <jwt>  Set session manually"))
    print()
    print(f"    {bold('logout')}     Logout and clear stored credentials")
    print()
    print(f"  {bold('APP MANAGEMENT')} {dim('(requires login)')}")
    print()
    print(f"    {bold('promote')}    Check promotion readiness or request promotion")
    print(dim("               cryptoserve promote <app-name> [options]"))
    print(dim("               --to <env>     Target environment"))
    print(dim("               --confirm      Proceed with promotion"))
    print(dim("               --expedite     Request expedited approval"))
    print()
    print(f"  {bold('SDK STATUS')}")
    print()
    print(f"    {bold('status')}     Show current configuration status")
    print(f"    {bold('verify')}     Verify SDK is working correctly")
    print(f"    {bold('info')}       Show current identity information")
    print(f"    {bold('contexts')}   List and search encryption contexts")
    print(dim("               cryptoserve contexts             # List all"))
    print(dim("               cryptoserve contexts \"email\"     # Search"))
    print(dim("               cryptoserve contexts -e user-pii # Example"))
    print()
    print(f"  {bold('SECURITY TOOLS')}")
    print()
    print(f"    {bold('scan')}       Scan for crypto libraries")
    print(f"    {bold('cbom')}       Generate Cryptographic Bill of Materials")
    print(dim("               --format json|cyclonedx|spdx"))
    print(dim("               --output <file>"))
    print()
    print(f"    {bold('pqc')}        Get PQC migration recommendations")
    print(dim("               --profile healthcare|financial|general"))
    print()
    print(f"    {bold('gate')}       CI/CD policy gate check")
    print(dim("               --policy strict|standard|permissive"))
    print(dim("               --format text|json|sarif"))
    print(dim("               --staged  Scan git staged files only"))
    print()
    print(f"  {bold('CERTIFICATES')}")
    print()
    print(f"    {bold('certs')}      Certificate operations")
    print(dim("               generate-csr   Generate CSR"))
    print(dim("               self-signed    Generate self-signed cert"))
    print(dim("               parse          Parse certificate"))
    print(dim("               verify         Verify certificate"))
    print()
    print(f"  {bold('BACKUP & RESTORE')} {dim('(requires admin)')}")
    print()
    print(f"    {bold('backup')}     Create encrypted database backup")
    print(dim("               --output <file>  Output path"))
    print(dim("               --audit-logs     Include audit logs"))
    print(dim("               --tenant-only    Backup current tenant only"))
    print()
    print(f"    {bold('restore')}    Restore from backup file")
    print(dim("               --backup <file>  Backup file path"))
    print(dim("               --dry-run        Preview what would be restored"))
    print()
    print(f"    {bold('backups')}    List available backups")
    print()
    print(f"  {bold('OFFLINE TOOLS')} {dim('(no server required)')}")
    print()
    print(f"    {bold('encrypt')}    Encrypt a string or file with a password")
    print(dim("               cryptoserve encrypt \"text\" --password <pw>"))
    print(dim("               cryptoserve encrypt --file <in> --output <out> --password <pw>"))
    print()
    print(f"    {bold('decrypt')}    Decrypt a string or file with a password")
    print(dim("               cryptoserve decrypt \"<base64>\" --password <pw>"))
    print(dim("               cryptoserve decrypt --file <in> --output <out> --password <pw>"))
    print()
    print(f"    {bold('hash-password')} Hash a password (scrypt or PBKDF2)")
    print(dim("               cryptoserve hash-password [password] [--algo scrypt|pbkdf2]"))
    print()
    print(f"    {bold('token')}      Create a JWT token (HS256)")
    print(dim("               cryptoserve token --key <secret> [--payload '{{...}}'] [--expires N]"))
    print()
    print(f"  {bold('OTHER')}")
    print()
    print(f"    {bold('wizard')}     Interactive context selection wizard")
    print(f"    {bold('help')}       Show this help message")
    print()
    return 0


# =============================================================================
# BACKUP COMMANDS
# =============================================================================

def cmd_backup():
    """Create encrypted backup of CryptoServe database."""
    import getpass
    import requests

    # Parse arguments
    output_path = None
    include_audit = False
    tenant_only = False

    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ("--output", "-o") and i + 1 < len(sys.argv):
            output_path = sys.argv[i + 1]
            i += 2
        elif arg == "--audit-logs":
            include_audit = True
            i += 1
        elif arg == "--tenant-only":
            tenant_only = True
            i += 1
        else:
            i += 1

    print(compact_header("BACKUP"))

    # Check login
    server = _get_server_url()
    cookie = _get_session_cookie()
    if not cookie:
        print(error("Not logged in. Run 'cryptoserve login' first."))
        return 1

    # Get backup password
    print()
    print(info("Backups are encrypted with a password you provide."))
    print(info("You'll need this password to restore the backup."))
    print()

    password = getpass.getpass("Enter backup password: ")
    if len(password) < 8:
        print(error("Password must be at least 8 characters."))
        return 1

    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print(error("Passwords do not match."))
        return 1

    print()
    print(info("Creating backup..."))

    try:
        resp = requests.post(
            f"{server}/api/admin/backups",
            cookies={"session": cookie},
            json={
                "password": password,
                "include_audit_logs": include_audit,
                "tenant_only": tenant_only,
            },
            timeout=300,  # 5 minute timeout for large backups
        )

        if resp.status_code == 401:
            print(error("Session expired. Please login again."))
            return 1

        if resp.status_code == 403:
            print(error("Admin access required for backup operations."))
            return 1

        data = resp.json()

        if not data.get("success"):
            print(error(f"Backup failed: {data.get('error', 'Unknown error')}"))
            return 1

        print()
        print(success("Backup created successfully!"))
        print()
        print(f"  Backup ID:     {bold(data['backup_id'])}")
        print(f"  Size:          {_format_size(data['size_bytes'])}")
        print(f"  Duration:      {data['duration_seconds']:.2f}s")
        print(f"  Tenants:       {data['tenant_count']}")
        print(f"  Contexts:      {data['context_count']}")
        print(f"  Keys:          {data['key_count']}")
        print(f"  PQC Keys:      {data['pqc_key_count']}")
        print(f"  Checksum:      {data['checksum'][:16]}...")
        print()

        # Download if output path specified
        if output_path:
            print(info(f"Downloading backup to {output_path}..."))
            download_resp = requests.get(
                f"{server}/api/admin/backups/{data['backup_id']}/download",
                cookies={"session": cookie},
                stream=True,
                timeout=300,
            )
            if download_resp.status_code == 200:
                with open(output_path, "wb") as f:
                    for chunk in download_resp.iter_content(chunk_size=64 * 1024):
                        f.write(chunk)
                print(success(f"Backup saved to: {output_path}"))
            else:
                print(warning(f"Failed to download: {download_resp.status_code}"))
        else:
            print(info(f"To download: cryptoserve backup --output backup.tar.gz.enc"))
            print(info(f"Or use: GET /api/admin/backups/{data['backup_id']}/download"))

        return 0

    except requests.exceptions.RequestException as e:
        print(error(f"Request failed: {e}"))
        return 1


def cmd_restore():
    """Restore from encrypted backup."""
    import getpass
    import requests

    # Parse arguments
    backup_path = None
    dry_run = True

    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ("--backup", "-b") and i + 1 < len(sys.argv):
            backup_path = sys.argv[i + 1]
            i += 2
        elif arg == "--dry-run":
            dry_run = True
            i += 1
        elif arg == "--execute":
            dry_run = False
            i += 1
        else:
            i += 1

    print(compact_header("RESTORE"))

    if not backup_path:
        print(error("Backup path required. Use --backup <file>"))
        print()
        print(info("Usage: cryptoserve restore --backup backup.tar.gz.enc"))
        print(info("       cryptoserve restore --backup backup.tar.gz.enc --execute"))
        return 1

    # Check login
    server = _get_server_url()
    cookie = _get_session_cookie()
    if not cookie:
        print(error("Not logged in. Run 'cryptoserve login' first."))
        return 1

    # For now, local file restore is not supported via API
    # The backup must be on the server
    print()
    print(warning("Note: Restore requires backup file to be on the server."))
    print(info("Upload the backup to the server's backup directory first."))
    print()

    # Extract backup ID from filename
    backup_id = os.path.basename(backup_path).replace(".tar.gz.enc", "")

    # Get password
    password = getpass.getpass("Enter backup password: ")

    if dry_run:
        print()
        print(info("Running in dry-run mode (no changes will be made)"))
        print(info("Use --execute to actually restore data"))

    print()
    print(info("Validating backup..."))

    try:
        # First, check backup info
        resp = requests.get(
            f"{server}/api/admin/backups/{backup_id}",
            params={"password": password},
            cookies={"session": cookie},
            timeout=60,
        )

        if resp.status_code == 404:
            print(error(f"Backup not found: {backup_id}"))
            print(info("Make sure the backup file is in the server's backup directory."))
            return 1

        if resp.status_code == 400:
            print(error("Invalid password or corrupted backup."))
            return 1

        if resp.status_code != 200:
            print(error(f"Failed to read backup: {resp.text}"))
            return 1

        manifest = resp.json()

        print()
        print(success("Backup validated successfully!"))
        print()
        print(f"  Version:       {manifest['version']}")
        print(f"  Created:       {manifest['created_at']}")
        print(f"  Database:      {manifest['database_type']}")
        print(f"  Tenants:       {manifest['tenant_count']}")
        print(f"  Contexts:      {manifest['context_count']}")
        print(f"  Keys:          {manifest['key_count']}")
        print(f"  PQC Keys:      {manifest['pqc_key_count']}")
        print(f"  Audit Logs:    {'Yes' if manifest['includes_audit_logs'] else 'No'}")
        print()

        # Perform restore
        print(info("Restoring..." if not dry_run else "Analyzing what would be restored..."))

        restore_resp = requests.post(
            f"{server}/api/admin/backups/{backup_id}/restore",
            cookies={"session": cookie},
            json={
                "backup_id": backup_id,
                "password": password,
                "dry_run": dry_run,
            },
            timeout=300,
        )

        if restore_resp.status_code != 200:
            print(error(f"Restore failed: {restore_resp.text}"))
            return 1

        result = restore_resp.json()

        if not result.get("success"):
            print(error(f"Restore failed: {result.get('error', 'Unknown error')}"))
            return 1

        print()
        if dry_run:
            print(success("Dry run complete - no changes made"))
        else:
            print(success("Restore completed successfully!"))

        print()
        print(f"  Duration: {result['duration_seconds']:.2f}s")
        print()
        print(f"  {'Would restore' if dry_run else 'Restored'}:")
        for table, count in result['records_restored'].items():
            print(f"    {table}: {count} records")

        if result.get('warnings'):
            print()
            print(warning("Warnings:"))
            for w in result['warnings']:
                print(f"    - {w}")

        return 0

    except requests.exceptions.RequestException as e:
        print(error(f"Request failed: {e}"))
        return 1


def cmd_backups():
    """List available backups."""
    import requests

    print(compact_header("BACKUPS"))

    # Check login
    server = _get_server_url()
    cookie = _get_session_cookie()
    if not cookie:
        print(error("Not logged in. Run 'cryptoserve login' first."))
        return 1

    try:
        resp = requests.get(
            f"{server}/api/admin/backups",
            cookies={"session": cookie},
            timeout=30,
        )

        if resp.status_code == 401:
            print(error("Session expired. Please login again."))
            return 1

        if resp.status_code == 403:
            print(error("Admin access required for backup operations."))
            return 1

        backups = resp.json()

        if not backups:
            print()
            print(info("No backups found."))
            print()
            print(info("Create a backup with: cryptoserve backup"))
            return 0

        print()
        print(f"  Found {bold(str(len(backups)))} backup(s):")
        print()

        for b in backups:
            print(f"  {bold(b['backup_id'])}")
            print(f"    Size:     {_format_size(b['size_bytes'])}")
            print(f"    Created:  {b['created_at']}")
            print()

        return 0

    except requests.exceptions.RequestException as e:
        print(error(f"Request failed: {e}"))
        return 1


def _format_size(size_bytes: int) -> str:
    """Format bytes as human-readable size."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


# =============================================================================
# Key Ceremony Commands (Enterprise Master Key Sharding)
# =============================================================================

def cmd_ceremony():
    """Key Ceremony operations for enterprise master key management.

    Subcommands:
        status      - Show ceremony status (initialized/sealed/unsealed)
        initialize  - Initialize master key with Shamir's Secret Sharing
        seal        - Seal the service (clear master key from memory)
        unseal      - Provide a share to unseal the service
        verify      - Verify a share without using it
        audit       - View ceremony audit log
    """
    import requests

    if len(sys.argv) < 3:
        _ceremony_help()
        return 0

    subcommand = sys.argv[2].lower()

    subcommands = {
        "status": _ceremony_status,
        "initialize": _ceremony_initialize,
        "seal": _ceremony_seal,
        "unseal": _ceremony_unseal,
        "verify": _ceremony_verify,
        "audit": _ceremony_audit,
        "help": _ceremony_help,
    }

    if subcommand in subcommands:
        return subcommands[subcommand]()
    else:
        print(error(f"Unknown ceremony subcommand: {subcommand}"))
        _ceremony_help()
        return 1


def _ceremony_help():
    """Show ceremony command help."""
    print(compact_header("KEY CEREMONY"))
    print()
    print("  Enterprise master key management using Shamir's Secret Sharing.")
    print("  Splits master key into shares requiring a threshold to unseal.")
    print()
    print("  Subcommands:")
    print(f"    {bold('status')}      Show ceremony status (initialized/sealed/unsealed)")
    print(f"    {bold('initialize')}  Initialize master key and generate recovery shares")
    print(f"    {bold('seal')}        Seal the service (clear master key from memory)")
    print(f"    {bold('unseal')}      Provide a recovery share to unseal the service")
    print(f"    {bold('verify')}      Verify a share is valid (without using it)")
    print(f"    {bold('audit')}       View ceremony audit log")
    print()
    print("  Examples:")
    print("    cryptoserve ceremony status")
    print("    cryptoserve ceremony initialize --threshold 3 --shares 5")
    print("    cryptoserve ceremony unseal --share <hex-share>")
    print()


def _ceremony_status():
    """Show key ceremony status."""
    import requests

    print(compact_header("CEREMONY STATUS"))

    server = _get_server_url()
    cookie = _get_session_cookie()
    if not cookie:
        print(error("Not logged in. Run 'cryptoserve login' first."))
        return 1

    try:
        resp = requests.get(
            f"{server}/api/admin/ceremony/status",
            cookies={"session": cookie},
            timeout=30,
        )

        if resp.status_code == 401:
            print(error("Session expired. Please login again."))
            return 1

        if resp.status_code == 403:
            print(error("Admin access required for ceremony operations."))
            return 1

        if resp.status_code != 200:
            print(error(f"Failed to get status: {resp.text}"))
            return 1

        data = resp.json()

        print()

        # State with visual indicator
        state = data["state"]
        if state == "uninitialized":
            print(f"  State:         {warning('UNINITIALIZED')}")
            print("                 Master key has not been created yet.")
        elif state == "sealed":
            print(f"  State:         {error('SEALED')}")
            print("                 Master key exists but is locked.")
        elif state == "unsealing":
            print(f"  State:         {warning('UNSEALING')}")
            progress = data.get("unseal_progress", {})
            print(f"                 {progress.get('shares_provided', 0)}/{progress.get('shares_required', 0)} shares provided.")
        elif state == "unsealed":
            print(f"  State:         {success('UNSEALED')}")
            print("                 Service is operational.")

        print()
        print(f"  Initialized:   {'Yes' if data['is_initialized'] else 'No'}")
        print(f"  Sealed:        {'Yes' if data['is_sealed'] else 'No'}")
        print(f"  Threshold:     {data['threshold']}-of-{data['total_shares']}")
        print(f"  Custodians:    {data['custodians']}")
        print()

        if data.get("unseal_progress"):
            progress = data["unseal_progress"]
            print(f"  Unseal Progress:")
            print(f"    Shares:      {progress['shares_provided']}/{progress['shares_required']}")
            pct = progress.get('progress_percent', 0)
            bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
            print(f"    Progress:    [{bar}] {pct:.0f}%")
            print()

        return 0

    except requests.exceptions.RequestException as e:
        print(error(f"Request failed: {e}"))
        return 1


def _ceremony_initialize():
    """Initialize master key with Shamir's Secret Sharing."""
    import requests
    import getpass

    print(compact_header("INITIALIZE KEY CEREMONY"))

    # Parse arguments
    threshold = 3
    total_shares = 5
    custodian_emails = []

    i = 3
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ("--threshold", "-t") and i + 1 < len(sys.argv):
            threshold = int(sys.argv[i + 1])
            i += 2
        elif arg in ("--shares", "-s") and i + 1 < len(sys.argv):
            total_shares = int(sys.argv[i + 1])
            i += 2
        elif arg == "--custodian" and i + 1 < len(sys.argv):
            custodian_emails.append(sys.argv[i + 1])
            i += 2
        else:
            i += 1

    server = _get_server_url()
    cookie = _get_session_cookie()
    if not cookie:
        print(error("Not logged in. Run 'cryptoserve login' first."))
        return 1

    print()
    print(warning("  ⚠ IMPORTANT: This operation can only be performed ONCE."))
    print()
    print(f"  You are about to initialize a {threshold}-of-{total_shares} threshold scheme.")
    print(f"  This means {total_shares} recovery shares will be generated,")
    print(f"  and any {threshold} of them can reconstruct the master key.")
    print()
    print("  The recovery shares will be displayed ONCE. Store them securely!")
    print()

    confirm = input("  Type 'INITIALIZE' to confirm: ")
    if confirm != "INITIALIZE":
        print(error("Initialization cancelled."))
        return 1

    try:
        resp = requests.post(
            f"{server}/api/admin/ceremony/initialize",
            cookies={"session": cookie},
            json={
                "threshold": threshold,
                "total_shares": total_shares,
                "custodian_emails": custodian_emails if custodian_emails else None,
            },
            timeout=60,
        )

        if resp.status_code == 401:
            print(error("Session expired. Please login again."))
            return 1

        if resp.status_code == 403:
            print(error("Admin access required for ceremony operations."))
            return 1

        if resp.status_code == 409:
            print(error("Master key already initialized. Use key rotation instead."))
            return 1

        if resp.status_code != 200:
            data = resp.json()
            print(error(f"Initialization failed: {data.get('detail', resp.text)}"))
            return 1

        data = resp.json()

        print()
        print(success("Master key initialized successfully!"))
        print()
        print(divider())
        print(bold("  RECOVERY SHARES - SAVE THESE SECURELY"))
        print(divider())
        print()

        for i, (share, fingerprint) in enumerate(zip(data["recovery_shares"], data["share_fingerprints"]), 1):
            print(f"  Share {i}:")
            print(f"    {share}")
            print(f"    Fingerprint: {fingerprint}")
            print()

        print(divider())
        print(bold("  ROOT TOKEN - SAVE THIS SECURELY"))
        print(divider())
        print()
        print(f"  {data['root_token']}")
        print()
        print(divider())
        print()
        print(warning("  These values will NOT be shown again!"))
        print("  Distribute shares to custodians via secure channels.")
        print()

        return 0

    except requests.exceptions.RequestException as e:
        print(error(f"Request failed: {e}"))
        return 1


def _ceremony_seal():
    """Seal the service (clear master key from memory)."""
    import requests

    print(compact_header("SEAL SERVICE"))

    server = _get_server_url()
    cookie = _get_session_cookie()
    if not cookie:
        print(error("Not logged in. Run 'cryptoserve login' first."))
        return 1

    print()
    print(warning("  ⚠ This will lock the service. All crypto operations will fail."))
    print("  Unseal with recovery shares to restore functionality.")
    print()

    confirm = input("  Type 'SEAL' to confirm: ")
    if confirm != "SEAL":
        print("Seal cancelled.")
        return 1

    try:
        resp = requests.post(
            f"{server}/api/admin/ceremony/seal",
            cookies={"session": cookie},
            timeout=30,
        )

        if resp.status_code == 401:
            print(error("Session expired. Please login again."))
            return 1

        if resp.status_code == 403:
            print(error("Admin access required for ceremony operations."))
            return 1

        if resp.status_code == 409:
            print(warning("Service is already sealed."))
            return 0

        if resp.status_code != 200:
            data = resp.json()
            print(error(f"Seal failed: {data.get('detail', resp.text)}"))
            return 1

        print()
        print(success("Service sealed. Master key cleared from memory."))
        print()
        print(info("Use 'cryptoserve ceremony unseal --share <share>' to unseal."))
        print()

        return 0

    except requests.exceptions.RequestException as e:
        print(error(f"Request failed: {e}"))
        return 1


def _ceremony_unseal():
    """Provide a recovery share to unseal the service."""
    import requests
    import getpass

    print(compact_header("UNSEAL SERVICE"))

    # Parse arguments
    share = None
    i = 3
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ("--share", "-s") and i + 1 < len(sys.argv):
            share = sys.argv[i + 1]
            i += 2
        else:
            i += 1

    server = _get_server_url()
    cookie = _get_session_cookie()
    if not cookie:
        print(error("Not logged in. Run 'cryptoserve login' first."))
        return 1

    # Prompt for share if not provided
    if not share:
        print()
        print(info("Enter your recovery share (or paste from secure storage):"))
        share = getpass.getpass("Share: ")

    if not share:
        print(error("No share provided."))
        return 1

    try:
        resp = requests.post(
            f"{server}/api/admin/ceremony/unseal",
            cookies={"session": cookie},
            json={"share": share.strip()},
            timeout=30,
        )

        if resp.status_code == 401:
            print(error("Session expired. Please login again."))
            return 1

        if resp.status_code == 403:
            print(error("Admin access required for ceremony operations."))
            return 1

        if resp.status_code == 409:
            print(warning("Service is already unsealed."))
            return 0

        if resp.status_code == 400:
            data = resp.json()
            print(error(f"Invalid share: {data.get('detail', 'Unknown error')}"))
            return 1

        if resp.status_code != 200:
            data = resp.json()
            print(error(f"Unseal failed: {data.get('detail', resp.text)}"))
            return 1

        data = resp.json()

        print()

        if data["is_sealed"]:
            print(success(f"Share accepted! {data['shares_provided']}/{data['shares_required']} shares provided."))
            remaining = data['shares_required'] - data['shares_provided']
            print(info(f"Need {remaining} more share(s) to unseal."))
            pct = data.get('progress_percent', 0)
            bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
            print(f"  Progress: [{bar}] {pct:.0f}%")
        else:
            print(success("Service unsealed! Master key is now available."))
            print()
            print(info("All crypto operations are now functional."))

        print()
        return 0

    except requests.exceptions.RequestException as e:
        print(error(f"Request failed: {e}"))
        return 1


def _ceremony_verify():
    """Verify a share is valid without using it."""
    import requests
    import getpass

    print(compact_header("VERIFY SHARE"))

    # Parse arguments
    share = None
    i = 3
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ("--share", "-s") and i + 1 < len(sys.argv):
            share = sys.argv[i + 1]
            i += 2
        else:
            i += 1

    server = _get_server_url()
    cookie = _get_session_cookie()
    if not cookie:
        print(error("Not logged in. Run 'cryptoserve login' first."))
        return 1

    # Prompt for share if not provided
    if not share:
        print()
        print(info("Enter share to verify:"))
        share = getpass.getpass("Share: ")

    if not share:
        print(error("No share provided."))
        return 1

    try:
        resp = requests.post(
            f"{server}/api/admin/ceremony/verify-share",
            cookies={"session": cookie},
            json={"share": share.strip()},
            timeout=30,
        )

        if resp.status_code == 401:
            print(error("Session expired. Please login again."))
            return 1

        if resp.status_code == 403:
            print(error("Admin access required for ceremony operations."))
            return 1

        if resp.status_code != 200:
            data = resp.json()
            print(error(f"Verification failed: {data.get('detail', resp.text)}"))
            return 1

        data = resp.json()

        print()

        if data["valid"]:
            print(success("Share is VALID"))
            print()
            print(f"  Share Index:       {data['share_index']}")
            print(f"  Fingerprint:       {data['fingerprint']}")
            print(f"  Parameters Match:  {'Yes' if data['params_match'] else 'No'}")
            print(f"  Fingerprint Valid: {'Yes' if data['fingerprint_valid'] else 'No'}")
        else:
            print(error("Share is INVALID"))
            if data.get("error"):
                print(f"  Error: {data['error']}")

        print()
        return 0

    except requests.exceptions.RequestException as e:
        print(error(f"Request failed: {e}"))
        return 1


def _ceremony_audit():
    """View ceremony audit log."""
    import requests

    print(compact_header("CEREMONY AUDIT LOG"))

    # Parse arguments
    limit = 20
    i = 3
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ("--limit", "-n") and i + 1 < len(sys.argv):
            limit = int(sys.argv[i + 1])
            i += 2
        else:
            i += 1

    server = _get_server_url()
    cookie = _get_session_cookie()
    if not cookie:
        print(error("Not logged in. Run 'cryptoserve login' first."))
        return 1

    try:
        resp = requests.get(
            f"{server}/api/admin/ceremony/audit",
            cookies={"session": cookie},
            params={"limit": limit},
            timeout=30,
        )

        if resp.status_code == 401:
            print(error("Session expired. Please login again."))
            return 1

        if resp.status_code == 403:
            print(error("Admin access required for ceremony operations."))
            return 1

        if resp.status_code != 200:
            data = resp.json()
            print(error(f"Failed to get audit log: {data.get('detail', resp.text)}"))
            return 1

        data = resp.json()
        events = data.get("events", [])

        print()

        if not events:
            print(dim("  No ceremony events recorded."))
        else:
            print(f"  Showing {len(events)} of {data.get('total', len(events))} events")
            print()

            for event in events:
                timestamp = event["timestamp"][:19].replace("T", " ")
                event_type = event["event_type"]
                actor = event["actor"]

                # Color by event type
                if event_type == "initialize":
                    type_str = success(event_type.upper())
                elif event_type == "seal":
                    type_str = error(event_type.upper())
                elif event_type in ("unseal_share", "unseal_complete"):
                    type_str = warning(event_type.upper())
                else:
                    type_str = event_type.upper()

                print(f"  {dim(timestamp)}  {type_str:20}  {actor}")

                # Show details for some events
                details = event.get("details", {})
                if details:
                    for k, v in details.items():
                        print(f"                            {dim(f'{k}: {v}')}")

        print()
        return 0

    except requests.exceptions.RequestException as e:
        print(error(f"Request failed: {e}"))
        return 1


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        cmd_help()
        return 0

    command = sys.argv[1].lower()

    commands = {
        "login": cmd_login,
        "logout": cmd_logout,
        "configure": cmd_configure,
        "status": cmd_status,
        "wizard": cmd_wizard,
        "contexts": cmd_contexts,
        "verify": cmd_verify,
        "info": cmd_info,
        "promote": cmd_promote,
        "scan": cmd_scan,
        "cbom": cmd_cbom,
        "pqc": cmd_pqc,
        "gate": cmd_gate,
        "certs": cmd_certs,
        "backup": cmd_backup,
        "restore": cmd_restore,
        "backups": cmd_backups,
        "ceremony": cmd_ceremony,
        # Offline tools
        "encrypt": cmd_encrypt,
        "decrypt": cmd_decrypt,
        "hash-password": cmd_hash_password,
        "token": cmd_token,
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
