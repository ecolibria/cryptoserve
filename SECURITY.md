# Security Policy

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in CryptoServe, please report it responsibly.

### How to Report

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email us at: **info@opena2a.org**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Fix Timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: Next release cycle

### Scope

This policy applies to:
- CryptoServe backend API
- Official Python and TypeScript SDKs
- Dashboard frontend
- Documentation site

### Out of Scope

- Third-party dependencies (report to respective maintainers)
- Social engineering attacks
- DoS attacks

## Security Best Practices

When using CryptoServe:

1. **Keep SDKs Updated**: Always use the latest SDK version
2. **Protect Master Key**: Never commit the master key to version control
3. **Use HTTPS**: Always use TLS in production
4. **Enable FIPS Mode**: For regulated environments, enable `FIPS_MODE=enabled`
5. **Review Audit Logs**: Regularly review encryption/decryption activity
6. **Rotate Keys**: Use the key rotation features periodically

## Security Documentation

For detailed security information, see:
- [Threat Model](docs/security/threat-model.md)
- [Technical Reference](docs/security/technical-reference.md)
- [Compliance Guide](docs/security/compliance.md)
- [Full Security Docs](https://ecolibria.github.io/crypto-serve/security/)

## Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers who report valid vulnerabilities (with permission).
