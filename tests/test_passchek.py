#!/usr/bin/env python3
"""
Module for testing the passchek module.
"""

import http.client
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from passchek.passchek import (
    __version__,
    get_matches,
    hash_password,
    main,
    pwned_count,
    reqst,
    usage,
)

# Constants
KNOWN_PASSWORDS = {
    "qwerty": ("B1B37", "73A05C0ED0176787A4F1574FF0075F7521E"),
    "password": ("5BAA6", "1E4C9B93F3F0682250B6CF8331B7EE68FD8"),
    "1234": ("7110E", "DA4D09E062AA5E4A390B0A572AC0D2C0220"),
}

MOCK_BODY = (
    "0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n"
    "1E4C9B93F3F0682250B6CF8331B7EE68FD8:7\r\n"  # suffix for "password"
    "011053FD0102E94D6AE2F8B83D76FAF94F6:1\r\n"
)

NUMBER = {2: 2, 5: 5, 7: 7, 35: 35}

# ---------------------------------------------------------------------------
# hash_password
# ---------------------------------------------------------------------------


class TestHashPassword:
    """Class for testing the hash_password function."""

    def test_known_vectors(self) -> None:
        for password, expected_hash in KNOWN_PASSWORDS.items():
            assert hash_password(password) == expected_hash

    def test_empty_string(self) -> None:
        prefix, suffix = hash_password("")
        assert len(prefix) == NUMBER[5]
        assert len(suffix) == NUMBER[35]
        assert (prefix + suffix) == "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"

    def test_returns_uppercase(self) -> None:
        prefix, suffix = hash_password("abc")
        assert prefix == prefix.upper()
        assert suffix == suffix.upper()

    def test_prefix_always_five_chars(self) -> None:
        for pw in ("a", "abc", "correct horse battery staple", "🔑"):
            prefix, suffix = hash_password(pw)
            assert len(prefix) == NUMBER[5]
            assert len(suffix) == NUMBER[35]

    def test_unicode_password(self) -> None:
        prefix, suffix = hash_password("pässwörд")
        assert len(prefix) == NUMBER[5]
        assert len(suffix) == NUMBER[35]


# ---------------------------------------------------------------------------
# reqst
# ---------------------------------------------------------------------------


class TestReqst:
    """Class for testing the reqst function."""

    @patch("passchek.passchek.urllib.request.urlopen")
    def test_returns_decoded_body(self, mock_urlopen: MagicMock) -> None:
        body = (
            b"0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n"
            b"00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r\n"
        )
        response = MagicMock()
        response.read.return_value = body
        mock_urlopen.return_value.__enter__.return_value = response

        result = reqst("0018A")

        assert result == body.decode("utf-8-sig")
        mock_urlopen.assert_called_once()

    @patch("passchek.passchek.urllib.request.urlopen")
    def test_request_url_contains_prefix(self, mock_urlopen: MagicMock) -> None:
        response = MagicMock()
        response.read.return_value = b""
        mock_urlopen.return_value.__enter__.return_value = response

        reqst("ABCDE")

        request = mock_urlopen.call_args.args[0]
        assert request.full_url.endswith("ABCDE")

    @patch("passchek.passchek.urllib.request.urlopen")
    def test_request_includes_required_headers(self, mock_urlopen: MagicMock) -> None:
        response = MagicMock()
        response.read.return_value = b""
        mock_urlopen.return_value.__enter__.return_value = response

        reqst("ABCDE")

        request = mock_urlopen.call_args.args[0]
        headers = {k.lower(): v for k, v in request.header_items()}
        assert headers.get("add-padding") == "true"
        user_agent = headers.get("user-agent")
        assert user_agent is not None and user_agent.startswith("passchek ")

    @patch(
        "passchek.passchek.urllib.request.urlopen",
        side_effect=urllib.error.URLError("unreachable"),
    )
    def test_url_error_exits_with_code_1(self, _: MagicMock) -> None:
        with pytest.raises(SystemExit) as exc:
            reqst("ABCDE")

        assert exc.value.code == 1

    @patch(
        "passchek.passchek.urllib.request.urlopen",
        side_effect=urllib.error.HTTPError(
            url="https://api.pwnedpasswords.com/range/ABCDE",
            code=500,
            msg="Server Error",
            hdrs=http.client.HTTPMessage(),
            fp=None,
        ),
    )
    def test_http_error_exits_with_code_1(self, _: MagicMock) -> None:
        with pytest.raises(SystemExit) as exc:
            reqst("ABCDE")

        assert exc.value.code == 1


# ---------------------------------------------------------------------------
# pwned_count
# ---------------------------------------------------------------------------


class TestPwnedCount:
    """Class for testing the pwned_count function."""

    @patch("passchek.passchek.reqst", return_value=MOCK_BODY)
    def test_found_returns_count(self, mockreqst: MagicMock) -> None:
        assert pwned_count("password") == NUMBER[7]
        mockreqst.assert_called_once_with("5BAA6")

    @patch("passchek.passchek.reqst", return_value=MOCK_BODY)
    def test_not_found_returns_zero(self, mockreqst: MagicMock) -> None:
        assert pwned_count("correct horse battery staple") == 0

    @patch("passchek.passchek.reqst", return_value="")
    def test_empty_response_returns_zero(self, _: MagicMock) -> None:
        assert pwned_count("anything") == 0

    @patch("passchek.passchek.reqst", return_value=MOCK_BODY)
    def test_callsreqst_with_correct_prefix(self, mockreqst: MagicMock) -> None:
        pwned_count("qwerty")
        mockreqst.assert_called_once_with("B1B37")

    @patch("passchek.passchek.reqst", return_value=MOCK_BODY)
    @patch("passchek.passchek.getpass.getpass", return_value="")
    def test_empty_password(self, mock_getpass: MagicMock, _: MagicMock) -> None:
        # Must not raise; result is 0 (empty string not in mock body)
        assert pwned_count(None) == 0


# ---------------------------------------------------------------------------
# get_matches
# ---------------------------------------------------------------------------


class TestReport:
    """Class for testing the get_matches function."""

    @patch("passchek.passchek.pwned_count", return_value=5)
    @patch("builtins.print")
    def test_prose_found(self, mock_print: MagicMock, _: MagicMock) -> None:
        get_matches(True, "password")
        mock_print.assert_called_once_with(
            "This password has appeared 5 times in data breaches."
        )

    @patch("passchek.passchek.pwned_count", return_value=0)
    @patch("builtins.print")
    def test_prose_not_found(self, mock_print: MagicMock, _: MagicMock) -> None:
        get_matches(True, "safe_password")
        mock_print.assert_called_once_with(
            "This password has not appeared in any data breaches!"
        )

    @patch("passchek.passchek.pwned_count", return_value=42)
    @patch("builtins.print")
    def test_count_only_found(self, mock_print: MagicMock, _: MagicMock) -> None:
        get_matches(False, "password")
        mock_print.assert_called_once_with(42)

    @patch("passchek.passchek.pwned_count", return_value=0)
    @patch("builtins.print")
    def test_count_only_not_found(self, mock_print: MagicMock, _: MagicMock) -> None:
        get_matches(False, "safe")
        mock_print.assert_called_once_with(0)


# ---------------------------------------------------------------------------
# usage
# ---------------------------------------------------------------------------


class TestUsage:
    """Class for testing the usage function."""

    @patch("builtins.print")
    def test_contains_version(self, mock_print: MagicMock) -> None:
        usage()
        output = mock_print.call_args[0][0]
        assert __version__ in output

    @patch("builtins.print")
    def test_contains_all_flags(self, mock_print: MagicMock) -> None:
        usage()
        output = mock_print.call_args[0][0]
        for flag in ("-h", "-n", "-p", "-s", "-v"):
            assert flag in output


# ---------------------------------------------------------------------------
# main — option parsing
# ---------------------------------------------------------------------------


class TestMain:
    """Class for testing the main function."""

    # -h / --help
    @patch("builtins.print")
    def test_help_short(self, mock_print: MagicMock) -> None:
        with patch("sys.argv", ["passchek", "-h"]):
            main()
        output = mock_print.call_args[0][0]
        assert __version__ in output

    @patch("builtins.print")
    def test_help_long(self, mock_print: MagicMock) -> None:
        with patch("sys.argv", ["passchek", "--help"]):
            main()
        output = mock_print.call_args[0][0]
        assert __version__ in output

    # -v / --version
    @patch("builtins.print")
    def test_version_short(self, mock_print: MagicMock) -> None:
        with patch("sys.argv", ["passchek", "-v"]):
            main()
        mock_print.assert_called_once_with(f"Passchek v{__version__}")

    @patch("builtins.print")
    def test_version_long(self, mock_print: MagicMock) -> None:
        with patch("sys.argv", ["passchek", "--version"]):
            main()
        mock_print.assert_called_once_with(f"Passchek v{__version__}")

    # unknown option
    def test_unknown_option_exits(self) -> None:
        with patch("sys.argv", ["passchek", "--unknown"]), pytest.raises(SystemExit):
            main()

    # -s / --sha1 with argument
    @patch("builtins.print")
    def test_sha1_with_arg(self, mock_print: MagicMock) -> None:
        with patch("sys.argv", ["passchek", "-s", "password"]):
            main()
        mock_print.assert_called_once_with(KNOWN_PASSWORDS["password"])

    @patch("builtins.print")
    def test_sha1_long_with_arg(self, mock_print: MagicMock) -> None:
        with patch("sys.argv", ["passchek", "--sha1", "qwerty"]):
            main()
        mock_print.assert_called_once_with(KNOWN_PASSWORDS["qwerty"])

    @patch("builtins.print")
    def test_sha1_multiple_args(self, mock_print: MagicMock) -> None:
        with patch("sys.argv", ["passchek", "-s", "password", "qwerty"]):
            main()
        assert mock_print.call_count == NUMBER[2]
        mock_print.assert_any_call(KNOWN_PASSWORDS["password"])
        mock_print.assert_any_call(KNOWN_PASSWORDS["qwerty"])

    # -s with --pipe
    @patch("builtins.print")
    def test_sha1_pipe(self, mock_print: MagicMock) -> None:
        stdin_lines = "password\nqwerty\n"
        with (
            patch("sys.argv", ["passchek", "-s", "-p"]),
            patch("sys.stdin", iter(stdin_lines.splitlines(keepends=True))),
        ):
            main()
        assert mock_print.call_count == NUMBER[2]

    # -s interactive (no args, no pipe)
    @patch("passchek.passchek.getpass.getpass", return_value="password")
    @patch("builtins.print")
    def test_sha1_interactive(self, mock_print: MagicMock, _: MagicMock) -> None:
        with patch("sys.argv", ["passchek", "-s"]):
            main()
        mock_print.assert_called_once_with(KNOWN_PASSWORDS["password"])

    # password as argument
    @patch("passchek.passchek.reqst", return_value=MOCK_BODY)
    @patch("builtins.print")
    def test_password_arg(self, mock_print: MagicMock, _: MagicMock) -> None:
        with patch("sys.argv", ["passchek", "password"]):
            main()
        mock_print.assert_called_once_with(
            "This password has appeared 7 times in data breaches."
        )

    # multiple password arguments
    @patch("passchek.passchek.reqst", return_value=MOCK_BODY)
    @patch("builtins.print")
    def test_multiple_password_args(self, mock_print: MagicMock, _: MagicMock) -> None:
        with patch("sys.argv", ["passchek", "password", "qwerty"]):
            main()
        assert mock_print.call_count == NUMBER[2]

    # -n / --num-only with argument
    @patch("passchek.passchek.reqst", return_value=MOCK_BODY)
    @patch("builtins.print")
    def test_num_only_short(self, mock_print: MagicMock, _: MagicMock) -> None:
        with patch("sys.argv", ["passchek", "-n", "password"]):
            main()
        mock_print.assert_called_once_with(7)

    @patch("passchek.passchek.reqst", return_value=MOCK_BODY)
    @patch("builtins.print")
    def test_num_only_long(self, mock_print: MagicMock, _: MagicMock) -> None:
        with patch("sys.argv", ["passchek", "--num-only", "password"]):
            main()
        mock_print.assert_called_once_with(7)

    # -p / --pipe
    @patch("passchek.passchek.reqst", return_value=MOCK_BODY)
    @patch("builtins.print")
    def test_pipe_short(self, mock_print: MagicMock, _: MagicMock) -> None:
        stdin_lines = "password\nqwerty\n"
        with (
            patch("sys.argv", ["passchek", "-p"]),
            patch("sys.stdin", iter(stdin_lines.splitlines(keepends=True))),
        ):
            main()
        assert mock_print.call_count == NUMBER[2]

    @patch("passchek.passchek.reqst", return_value=MOCK_BODY)
    @patch("builtins.print")
    def test_pipe_long(self, mock_print: MagicMock, _: MagicMock) -> None:
        stdin_lines = "password\n"
        with (
            patch("sys.argv", ["passchek", "--pipe"]),
            patch("sys.stdin", iter(stdin_lines.splitlines(keepends=True))),
        ):
            main()
        mock_print.assert_called_once_with(
            "This password has appeared 7 times in data breaches."
        )

    # -p combined with -n
    @patch("passchek.passchek.reqst", return_value=MOCK_BODY)
    @patch("builtins.print")
    def test_pipe_and_num_only(self, mock_print: MagicMock, _: MagicMock) -> None:
        with (
            patch("sys.argv", ["passchek", "-p", "-n"]),
            patch("sys.stdin", iter(["password\n"])),
        ):
            main()
        mock_print.assert_called_once_with(7)

    # interactive prompt (no args, no pipe)
    @patch("passchek.passchek.getpass.getpass", return_value="password")
    @patch("passchek.passchek.reqst", return_value=MOCK_BODY)
    @patch("builtins.print")
    def test_interactive_prompt(
        self, mock_print: MagicMock, _: MagicMock, mock_getpass: MagicMock
    ) -> None:
        with patch("sys.argv", ["passchek"]):
            main()
        mock_getpass.assert_called_once()
        mock_print.assert_called_once_with(
            "This password has appeared 7 times in data breaches."
        )

    # pipe preserves leading/trailing spaces in password (rstrip("\n") not strip())
    @patch("passchek.passchek.reqst", return_value="")
    @patch("builtins.print")
    def test_pipe_preserves_spaces(self, _: str, mockreqst: MagicMock) -> None:
        with (
            patch("sys.argv", ["passchek", "-p"]),
            patch("sys.stdin", iter([" password \n"])),
        ):
            main()
        called_prefix, _ = hash_password(" password ")
        mockreqst.assert_called_once_with(called_prefix)
