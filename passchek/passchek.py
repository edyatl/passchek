#!/usr/bin/env python3
"""
Passchek is a simple cli tool, checks if your password has been compromised.

This tool utilizes the k-anonymity algorithm to query Troy Hunt's
pwnedpassword API for password breaches.

MIT License

Developed by @edyatl <edyatl@yandex.ru> March 2023
https://github.com/edyatl

"""
import os
import getpass
import urllib.error
import urllib.request
import sys
import hashlib
import getopt


__version__ = "0.2.3"

_API = "https://api.pwnedpasswords.com/range/"


def usage() -> None:
    """Show usage help screen and exit."""
    print(f"""Passchek is a simple cli tool, checks if your password has been compromised.

Usage: {os.path.basename(__file__)} [options] [PASSWORD ...]

Options:
    -h, --help      Shows this help message and exit
    -n, --num-only  Set output without accompanying text
    -p, --pipe      For use in shell pipes, read stdin
    -s, --sha1      Shows SHA1 hash in tuple ('prefix', 'suffix') and exit
    -v, --version   Shows current version of the program and exit
""")


def hash_password(raw_pass: str | None = None) -> tuple[str, str]:
    """Hashing raw password and split hash to prefix and suffix.

    :param raw_pass: password in raw format
    :return: tuple (prefix of hash, suffix of hash)
    """
    raw_pass = raw_pass if raw_pass else ""
    hash_pass = hashlib.sha1(raw_pass.encode("utf-8"), usedforsecurity=True).hexdigest().upper()
    return hash_pass[:5], hash_pass[5:]


def open_prompt_dialog() -> tuple[str, str]:
    """Open prompt dialog for enter password.

    :return: result tuple of hash_password (prefix of hash, suffix of hash)
    """
    raw_pass = getpass.getpass("Enter password: ")
    return hash_password(raw_pass)


def reqst(prefix: str) -> str:
    """Make request to Troy Hunt's pwnedpassword API.

    :param prefix: prefix of password hash
    :return: response string of Troy Hunt's pwnedpassword API
    """
    req = urllib.request.Request(
        url=_API + prefix,
        headers={
            "User-Agent": "passchek " + __version__ + " (Python)",
            "Add-Padding": "true",
        },
    )
    try:
        with urllib.request.urlopen(req) as res:
            return res.read().decode("utf-8-sig")
    except (urllib.error.HTTPError, urllib.error.URLError) as err:
        print("Exception found: {}".format(err))
        sys.exit(1)


def pwned_count(password: str) -> int:
    """Return how many times *password* appears in breach data (0 = not found).

    :param passwrd: password in raw format
    :return: count of matches
    """
    if password:
        prefix, suffix = hash_password(password)
    else:
        prefix, suffix = open_prompt_dialog()

    for line in reqst(prefix).splitlines():
        tail, sep, count = line.partition(":")
        if tail == suffix:
            return int(count)
    return 0


def get_matches(text_output: bool = True, passwrd: str | None = None) -> None:
    """Print the number of pwned-password matches.

    :param text_output: Whether to print a human-readable message.
    :param passwrd: Password in raw format.
    """
    matches = pwned_count(passwrd)

    if text_output:
        print(
            f"This password has appeared {matches} times in data breaches."
            if matches
            else "This password has not appeared in any data breaches!"
        )
    else:
        print(matches)


def handle_sha1_option(text_output: bool, use_in_pipe: bool, args: list[str]) -> None:
    """Handle the --sha1 option."""

    def emit(password: str) -> None:
        result = hash_password(password)
        print(result if text_output else " ".join(result))

    if args:
        for arg in args:
            emit(arg)
        sys.exit()

    if use_in_pipe:
        for line in sys.stdin:
            emit(line.strip())
        sys.exit()

    emit(open_prompt_dialog())
    sys.exit()


def main() -> None:
    """Define entry point of program."""
    # Set default flags for options
    text_output: bool = True  # --num-only
    use_in_pipe: bool = False  # --pipe
    sha1_output: bool = False  # --sha1

    # Parse command line arguments and options
    try:
        opts, args = getopt.gnu_getopt(
            sys.argv[1:], "hnpsv", ["help", "num-only", "pipe", "sha1", "version"]
        )
    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)  # will print something like "option -x not recognized"
        usage()
        sys.exit(2)

    for opt, _ in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-n", "--num-only"):
            text_output = False
        elif opt in ("-p", "--pipe"):
            use_in_pipe = True
        elif opt in ("-s", "--sha1"):
            sha1_output = True
        elif opt in ("-v", "--version"):
            print("Passchek version: %s" % __version__)
            sys.exit()

    # Handle --sha1 option
    if sha1_output:
        handle_sha1_option(text_output, use_in_pipe, args)

    # Handle password(s) arguments
    if args:
        for _arg in args:
            get_matches(text_output, _arg)
        sys.exit()

    # Handle piping
    if use_in_pipe:
        for pass_line in sys.stdin.readlines():
            get_matches(text_output, pass_line.strip())
        sys.exit()

    # Prompt user for password
    get_matches(text_output)


if __name__ == "__main__":
    main()
