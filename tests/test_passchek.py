#!/usr/bin/env python3
import sys
import pytest
import urllib.error
import unittest.mock as mock
from unittest.mock import patch, MagicMock, call
from passchek.passchek import (
    hash_password,
    pwned_count,
    reqst,
    get_matches,
    usage,
    main,
    __version__,
)


# ---------------------------------------------------------------------------
# hash_password
# ---------------------------------------------------------------------------

class TestHashPassword:
    def test_known_vectors(self):
        assert hash_password("qwerty") == ("B1B37", "73A05C0ED0176787A4F1574FF0075F7521E")
        assert hash_password("password") == ("5BAA6", "1E4C9B93F3F0682250B6CF8331B7EE68FD8")
        assert hash_password("1234") == ("7110E", "DA4D09E062AA5E4A390B0A572AC0D2C0220")

    def test_empty_string(self):
        prefix, suffix = hash_password("")
        assert len(prefix) == 5
        assert len(suffix) == 35
        assert (prefix + suffix) == "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"

    def test_returns_uppercase(self):
        prefix, suffix = hash_password("abc")
        assert prefix == prefix.upper()
        assert suffix == suffix.upper()

    def test_prefix_always_five_chars(self):
        for pw in ("a", "abc", "correct horse battery staple", "🔑"):
            prefix, suffix = hash_password(pw)
            assert len(prefix) == 5
            assert len(suffix) == 35

    def test_unicode_password(self):
        prefix, suffix = hash_password("pässwörд")
        assert len(prefix) == 5
        assert len(suffix) == 35


# ---------------------------------------------------------------------------
# reqst
# ---------------------------------------------------------------------------

class TestReqst:
    @patch("passchek.passchek.urllib.request.urlopen")
    def test_returns_decoded_body(self, mock_urlopen):
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
    def test_request_url_contains_prefix(self, mock_urlopen):
        response = MagicMock()
        response.read.return_value = b""
        mock_urlopen.return_value.__enter__.return_value = response

        reqst("ABCDE")

        request = mock_urlopen.call_args.args[0]
        assert request.full_url.endswith("ABCDE")

    @patch("passchek.passchek.urllib.request.urlopen")
    def test_request_includes_required_headers(self, mock_urlopen):
        response = MagicMock()
        response.read.return_value = b""
        mock_urlopen.return_value.__enter__.return_value = response

        reqst("ABCDE")

        request = mock_urlopen.call_args.args[0]
        headers = {k.lower(): v for k, v in request.header_items()}
        assert headers.get("add-padding") == "true"
        assert headers.get("user-agent").startswith("passchek ")

    @patch(
        "passchek.passchek.urllib.request.urlopen",
        side_effect=urllib.error.URLError("unreachable"),
    )
    def test_url_error_exits_with_code_1(self, _):
        with pytest.raises(SystemExit) as exc:
            reqst("ABCDE")

        assert exc.value.code == 1

    @patch(
        "passchek.passchek.urllib.request.urlopen",
        side_effect=urllib.error.HTTPError(
            url="https://api.pwnedpasswords.com/range/ABCDE",
            code=500,
            msg="Server Error",
            hdrs=None,
            fp=None,
        ),
    )
    def test_http_error_exits_with_code_1(self, _):
        with pytest.raises(SystemExit) as exc:
            reqst("ABCDE")

        assert exc.value.code == 1


# ---------------------------------------------------------------------------
# pwned_count
# ---------------------------------------------------------------------------

MOCK_BODY = (
    "0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n"
    "1E4C9B93F3F0682250B6CF8331B7EE68FD8:7\r\n"   # suffix for "password"
    "011053FD0102E94D6AE2F8B83D76FAF94F6:1\r\n"
)

class TestPwnedCount:
    @patch("passchek.passchek.reqst", return_value=MOCK_BODY)
    def test_found_returns_count(self, mockreqst):
        assert pwned_count("password") == 7
        mockreqst.assert_called_once_with("5BAA6")

    @patch("passchek.passchek.reqst", return_value=MOCK_BODY)
    def test_not_found_returns_zero(self, mockreqst):
        assert pwned_count("correct horse battery staple") == 0

    @patch("passchek.passchek.reqst", return_value="")
    def test_empty_response_returns_zero(self, _):
        assert pwned_count("anything") == 0

    @patch("passchek.passchek.reqst", return_value=MOCK_BODY)
    def test_callsreqst_with_correct_prefix(self, mockreqst):
        pwned_count("qwerty")
        mockreqst.assert_called_once_with("B1B37")

    @patch("passchek.passchek.reqst", return_value=MOCK_BODY)
    @patch("passchek.passchek.getpass.getpass", return_value="")
    def test_empty_password(self, mock_getpass, _):
        # Must not raise; result is 0 (empty string not in mock body)
        assert pwned_count(None) == 0


# ---------------------------------------------------------------------------
# get_matches
# ---------------------------------------------------------------------------

class TestReport:
    @patch("passchek.passchek.pwned_count", return_value=5)
    @patch("builtins.print")
    def test_prose_found(self, mock_print, _):
        get_matches("password", count_only=False)
        mock_print.assert_called_once_with(
            "This password has appeared 5 times in data breaches."
        )

    @patch("passchek.passchek.pwned_count", return_value=0)
    @patch("builtins.print")
    def test_prose_not_found(self, mock_print, _):
        get_matches("safe_password", count_only=False)
        mock_print.assert_called_once_with(
            "This password has not appeared in any data breaches!"
        )

    @patch("passchek.passchek.pwned_count", return_value=42)
    @patch("builtins.print")
    def test_count_only_found(self, mock_print, _):
        get_matches("password", count_only=True)
        mock_print.assert_called_once_with(42)

    @patch("passchek.passchek.pwned_count", return_value=0)
    @patch("builtins.print")
    def test_count_only_not_found(self, mock_print, _):
        get_matches("safe", count_only=True)
        mock_print.assert_called_once_with(0)


# ---------------------------------------------------------------------------
# usage
# ---------------------------------------------------------------------------

class TestUsage:
    @patch("builtins.print")
    def test_contains_version(self, mock_print):
        usage()
        output = mock_print.call_args[0][0]
        assert __version__ in output

    @patch("builtins.print")
    def test_contains_all_flags(self, mock_print):
        usage()
        output = mock_print.call_args[0][0]
        for flag in ("-h", "-n", "-p", "-s", "-v"):
            assert flag in output


# ---------------------------------------------------------------------------
# main — option parsing
# ---------------------------------------------------------------------------

class TestMain:
    # -h / --help
    @patch("builtins.print")
    def test_help_short(self, mock_print):
        with patch("sys.argv", ["passchek", "-h"]):
            main()
        output = mock_print.call_args[0][0]
        assert __version__ in output

    @patch("builtins.print")
    def test_help_long(self, mock_print):
        with patch("sys.argv", ["passchek", "--help"]):
            main()
        output = mock_print.call_args[0][0]
        assert __version__ in output

    # -v / --version
    @patch("builtins.print")
    def test_version_short(self, mock_print):
        with patch("sys.argv", ["passchek", "-v"]):
            main()
        mock_print.assert_called_once_with(f"passchek {__version__}")

    @patch("builtins.print")
    def test_version_long(self, mock_print):
        with patch("sys.argv", ["passchek", "--version"]):
            main()
        mock_print.assert_called_once_with(f"passchek {__version__}")

    # unknown option
    def test_unknown_option_exits(self):
        with patch("sys.argv", ["passchek", "--unknown"]):
            with pytest.raises(SystemExit):
                main()

    # -s / --sha1 with argument
    @patch("builtins.print")
    def test_sha1_with_arg(self, mock_print):
        with patch("sys.argv", ["passchek", "-s", "password"]):
            main()
        mock_print.assert_called_once_with("5BAA6", "1E4C9B93F3F0682250B6CF8331B7EE68FD8")

    @patch("builtins.print")
    def test_sha1_long_with_arg(self, mock_print):
        with patch("sys.argv", ["passchek", "--sha1", "qwerty"]):
            main()
        mock_print.assert_called_once_with("B1B37", "73A05C0ED0176787A4F1574FF0075F7521E")

    @patch("builtins.print")
    def test_sha1_multiple_args(self, mock_print):
        with patch("sys.argv", ["passchek", "-s", "password", "qwerty"]):
            main()
        assert mock_print.call_count == 2
        mock_print.assert_any_call("5BAA6", "1E4C9B93F3F0682250B6CF8331B7EE68FD8")
        mock_print.assert_any_call("B1B37", "73A05C0ED0176787A4F1574FF0075F7521E")

    # -s with --pipe
    @patch("builtins.print")
    def test_sha1_pipe(self, mock_print):
        stdin_lines = "password\nqwerty\n"
        with patch("sys.argv", ["passchek", "-s", "-p"]):
            with patch("sys.stdin", iter(stdin_lines.splitlines(keepends=True))):
                main()
        assert mock_print.call_count == 2

    # -s interactive (no args, no pipe)
    @patch("passchek.passchek.getpass.getpass", return_value="password")
    @patch("builtins.print")
    def test_sha1_interactive(self, mock_print, _):
        with patch("sys.argv", ["passchek", "-s"]):
            main()
        mock_print.assert_called_once_with("5BAA6", "1E4C9B93F3F0682250B6CF8331B7EE68FD8")

    # password as argument
    @patch("passchek.passchek.reqst", return_value=MOCK_BODY)
    @patch("builtins.print")
    def test_password_arg(self, mock_print, _):
        with patch("sys.argv", ["passchek", "password"]):
            main()
        mock_print.assert_called_once_with(
            "This password has appeared 7 times in data breaches."
        )

    # multiple password arguments
    @patch("passchek.passchek.reqst", return_value=MOCK_BODY)
    @patch("builtins.print")
    def test_multiple_password_args(self, mock_print, _):
        with patch("sys.argv", ["passchek", "password", "qwerty"]):
            main()
        assert mock_print.call_count == 2

    # -n / --num-only with argument
    @patch("passchek.passchek.reqst", return_value=MOCK_BODY)
    @patch("builtins.print")
    def test_num_only_short(self, mock_print, _):
        with patch("sys.argv", ["passchek", "-n", "password"]):
            main()
        mock_print.assert_called_once_with(7)

    @patch("passchek.passchek.reqst", return_value=MOCK_BODY)
    @patch("builtins.print")
    def test_num_only_long(self, mock_print, _):
        with patch("sys.argv", ["passchek", "--num-only", "password"]):
            main()
        mock_print.assert_called_once_with(7)

    # -p / --pipe
    @patch("passchek.passchek.reqst", return_value=MOCK_BODY)
    @patch("builtins.print")
    def test_pipe_short(self, mock_print, _):
        stdin_lines = "password\nqwerty\n"
        with patch("sys.argv", ["passchek", "-p"]):
            with patch("sys.stdin", iter(stdin_lines.splitlines(keepends=True))):
                main()
        assert mock_print.call_count == 2

    @patch("passchek.passchek.reqst", return_value=MOCK_BODY)
    @patch("builtins.print")
    def test_pipe_long(self, mock_print, _):
        stdin_lines = "password\n"
        with patch("sys.argv", ["passchek", "--pipe"]):
            with patch("sys.stdin", iter(stdin_lines.splitlines(keepends=True))):
                main()
        mock_print.assert_called_once_with(
            "This password has appeared 7 times in data breaches."
        )

    # -p combined with -n
    @patch("passchek.passchek.reqst", return_value=MOCK_BODY)
    @patch("builtins.print")
    def test_pipe_and_num_only(self, mock_print, _):
        with patch("sys.argv", ["passchek", "-p", "-n"]):
            with patch("sys.stdin", iter(["password\n"])):
                main()
        mock_print.assert_called_once_with(7)

    # interactive prompt (no args, no pipe)
    @patch("passchek.passchek.getpass.getpass", return_value="password")
    @patch("passchek.passchek.reqst", return_value=MOCK_BODY)
    @patch("builtins.print")
    def test_interactive_prompt(self, mock_print, _, mock_getpass):
        with patch("sys.argv", ["passchek"]):
            main()
        mock_getpass.assert_called_once()
        mock_print.assert_called_once_with(
            "This password has appeared 7 times in data breaches."
        )

    # pipe preserves leading/trailing spaces in password (rstrip("\n") not strip())
    @patch("passchek.passchek.reqst", return_value="")
    @patch("builtins.print")
    def test_pipe_preserves_spaces(self, _, mockreqst):
        with patch("sys.argv", ["passchek", "-p"]):
            with patch("sys.stdin", iter([" password \n"])):
                main()
        called_prefix = mockreqst.call_args[0][0]
        expected_prefix, _ = hash_password(" password ")
        assert called_prefix == expected_prefix
