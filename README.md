# Passchek

> A privacy-first CLI tool for checking whether a password has appeared in known data breaches using Troy Hunt's Pwned Passwords API and the k-anonymity model.

[![Version](https://img.shields.io/badge/version-v0.2.3-blue)](https://github.com/edyatl/passchek)
[![Python](https://img.shields.io/badge/python-3.9%20--%203.14-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Passchek securely checks passwords against the [Have I Been Pwned Pwned Passwords API](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange) without ever sending the full password, or even the full SHA-1 hash, over the network.

The project is intentionally designed so that users can quickly audit the full source code themselves. Since real passwords and user trust are involved, the implementation follows strict engineering principles:

## Design Principles

1. **Conciseness**
   The code stays as short as possible while preserving readability. No unnecessary layers, abstractions, or dead code.

2. **Clarity**
   A novice Python developer should be able to understand the whole program in under a minute. The structure is intentionally simple, PEP 8 compliant, and self-explanatory.

3. **Leanness**
   Every function, import, and constant must justify its existence. Anything non-essential is removed.

4. **Embeddability**
   The core breach-check logic is trivially reusable as a small importable function for CI/CD, scripts, web backends, or other automation.

5. **Professional suitability**
   The codebase follows production-grade engineering expectations: clear control flow, minimal side effects, strong typing, predictable behavior, robust error handling, and idiomatic Python.

6. **Security**
   Password exposure risk is minimized through hidden prompt input, reduced plaintext copies, no logging, no unnecessary I/O, local suffix matching, and careful hashing flow.

7. **Independence**
   Passchek uses only the Python standard library and targets Python 3.9+.

8. **Speed**
   Response parsing uses early exits, minimal allocations, efficient iteration, and reduced memory copies for the fastest possible standard-library implementation.

These principles make it easy for users to personally verify that the application behaves safely.

---

## Features

* Secure password breach checks using the k-anonymity protocol
* Check single or multiple passwords
* Read passwords from stdin and shell pipes
* Numeric-only output for scripting
* SHA-1 prefix/suffix output without network access
* Fast early-exit response parsing
* Python 3.9 through 3.14 support
* Modern PyPI package installation
* Zero third-party runtime dependencies

---

## How It Works

1. Hash the password with SHA-1
2. Split the hash into:

   * first 5 characters as prefix
   * remaining 35 characters as suffix
3. Send only the prefix to the API
4. Compare suffixes locally
5. Return the breach count

The full password never leaves the local machine.

---

## Installation

### From PyPI

```bash
python3 -m pip install --upgrade passchek
```

Or for the current user only:

```bash
python3 -m pip install --user passchek
```

### Verify installation

```bash
passchek --version
```

Expected output:

```bash
Passchek v0.2.3
```

### From source

```bash
git clone https://github.com/edyatl/passchek.git
cd passchek
python3 -m pip install .
```

Note: `pip search` is no longer supported by PyPI. Use `pip show passchek` or `passchek --version` instead.

---

## Usage

```text
Usage:
    passchek [options] [PASSWORD ...]

Arguments:
    PASSWORD    One or more passwords to check.
                If omitted, Passchek reads from prompt or stdin.

Options:
    -h, --help       Show help and exit
    -n, --num-only   Output only breach count numbers
    -p, --pipe       Read passwords from stdin / shell pipe
    -s, --sha1       Print SHA-1 hash as prefix/suffix and exit
    -v, --version    Show Passchek version
```

---

## Examples

### Interactive prompt

```bash
$ passchek
Enter password:
This password has appeared 3912816 times in data breaches.
```

### Numeric output only

```bash
$ passchek -n
Enter password:
3912816
```

### SHA-1 tuple mode

```bash
$ passchek -s
Enter password:
('B1B37', '73A05C0ED0176787A4F1574FF0075F7521E')
```

### Multiple passwords

```bash
$ passchek -n qwerty ytrewq qazwsx random_password
3912816
33338
505344
0
```

### Pipe mode

```bash
$ cat passwords.txt | passchek -np
21
8
0
0
457
```

---

## Security Notes

The safest way to use Passchek is interactive prompt mode:

```bash
passchek
```

This avoids shell history leakage and keeps input hidden.

Avoid passing real passwords as command-line arguments:

```bash
passchek my-secret-password
```

Shell history may store plaintext values.

Prefer:

* interactive prompt
* stdin pipe
* secret injection from secure automation environments

---

## Windows

Install Python 3.9+ from:

[https://www.python.org/downloads/windows/](https://www.python.org/downloads/windows/)

Then install:

```powershell
py -m pip install passchek
```

Run:

```powershell
passchek
```

---

## Changelog

## v0.2.3 (2026-04-10)

A major refactoring and modernization release focused on maintainability, packaging, typing, and Python 3.14 readiness.

### Added

* Python 3.9+ built-in generics support
* package-style versioning via `passchek._version.__version__`
* improved MANIFEST and PyPI packaging flow
* better CLI version and help formatting
* comprehensive type hints in source and tests
* linter, formatter, and pre-commit configuration

### Changed

* refactored `main()` into smaller focused units
* replaced legacy URL helpers with `_API` constant and f-strings
* optimized response parsing with `splitlines()` and `partition()`
* early exit on first suffix match
* modernized packaging from `setup.py` to `pyproject.toml`
* improved SHA-1 handling with `usedforsecurity=True`

### Fixed

* corrected password whitespace stripping
* improved pipe newline handling
* better empty-password test behavior
* more robust urllib error handling
* consistent non-zero CLI exit codes

---

## Contributing

Contributions are welcome.

Areas especially appreciated:

* security review
* performance review
* code simplification
* packaging improvements
* test coverage

Repository:

[https://github.com/edyatl/passchek](https://github.com/edyatl/passchek)

---

## Acknowledgements

Thanks to [Troy Hunt](https://www.troyhunt.com) for the Pwned Passwords API.

Thanks to [James Ridgway](https://github.com/jamesridgway) for the original shell-script inspiration.

---

## Author

**Yevgeny Dyatlov**

GitHub: [https://github.com/edyatl](https://github.com/edyatl)

---

## License

MIT License

Copyright (c) 2020-2026 Yevgeny Dyatlov

See [LICENSE](LICENSE) for details.
