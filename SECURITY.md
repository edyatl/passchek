# Security Policy

## Supported Versions

Only the latest release receives security fixes.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Report privately via [GitHub Security Advisories](../../security/advisories/new) or email the maintainer directly. Please include:

- A clear description of the vulnerability
- Steps to reproduce
- Potential impact

## Design Notes

- Passwords are never logged, cached, or transmitted in plaintext.
- Only the first 5 hex characters of the SHA-1 hash are sent to the HaveIBeenPwned API (k-anonymity model).
- No third-party dependencies — standard library only.
