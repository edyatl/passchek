#!/usr/bin/env python3
import pytest

# import io
import unittest.mock as mock
from unittest.mock import patch, mock_open, MagicMock
from click.testing import CliRunner

# import passchek.passchek as app
from passchek.passchek import *


def test_hash_password():
    assert hash_password("qwerty") == ("B1B37", "73A05C0ED0176787A4F1574FF0075F7521E")
    assert hash_password("password") == ("5BAA6", "1E4C9B93F3F0682250B6CF8331B7EE68FD8")
    assert hash_password("1234") == ("7110E", "DA4D09E062AA5E4A390B0A572AC0D2C0220")


def test_url_join():
    assert url_join("range", "B1B37") == "https://api.pwnedpasswords.com/range/B1B37"
    assert url_join("range", "5BAA6") == "https://api.pwnedpasswords.com/range/5BAA6"


def test_convert_key_val_tpl():
    assert convert_key_val_tpl("08613D876336B480896C990CCC9451C66C5:12") == (
        "08613D876336B480896C990CCC9451C66C5",
        12,
    )
    assert convert_key_val_tpl("34ECD5DC2D7B0ECE7998AFB5C7AFC33A7AFD7:10") == (
        "34ECD5DC2D7B0ECE7998AFB5C7AFC33A7AFD7",
        10,
    )


@patch("passchek.passchek.urllib.request.urlopen")
def test_reqst(mock_urlopen):
    response_text = b"0018A45C4D1DEF81644B54AB7F969B88D65:1\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\n011053FD0102E94D6AE2F8B83D76FAF94F6:1\n"
    cm = MagicMock()
    cm.getcode.return_value = 200
    cm.read.return_value = response_text
    cm.__enter__.return_value = cm
    mock_urlopen.return_value = cm

    response = reqst("0018A")
    assert response == response_text.decode("utf-8-sig")
    mock_urlopen.assert_called_once()


@patch("passchek.passchek.reqst")
@patch("passchek.passchek.getpass.getpass", return_value="password")
@patch("builtins.print")
def test_get_matches(mock_print, mock_getpass, mock_reqst):
    mock_reqst.return_value = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:2\r\n011053FD0102E94D6AE2F8B83D76FAF94F6:1"
    get_matches(True)
    mock_reqst.assert_called_once_with("range", "5BAA6")
    # Test case 1: Password has matches in pwnedpassword DB
    mock_print.assert_called_once_with(
        "This password has appeared 2 times in data breaches."
    )
    mock_reqst.assert_called_once()

    # Test case 2: Password has no matches in pwnedpassword DB
    mock_reqst.return_value = ""
    get_matches(True)
    mock_print.assert_called_with(
        "This password has not appeared in any data breaches!"
    )
    mock_reqst.assert_called()

    # Test case 3: Password is None
    mock_getpass.return_value = None
    get_matches(True)
    mock_print.assert_called_with(
        "This password has not appeared in any data breaches!"
    )
    mock_reqst.assert_called()

    # Test case 4: Text output is False
    get_matches()
    mock_print.assert_called_with("0")
    mock_reqst.assert_called()


# @patch("passchek.passchek.get_matches")
# def test_main_with_password(mock_get_matches):
# mock_get_matches.return_value = None
# runner = CliRunner()
# result = runner.invoke(passchek, ["mypassword"])
# assert result.exit_code == 0
# assert mock_get_matches.call_count == 1

# @mock.patch('passchek.passchek.open_prompt_dialog', return_value='password123')
# @mock.patch('passchek.passchek.get_matches', return_value=None)
# @mock.patch('builtins.print')
# def test_main(mock_print, mock_get_matches, mock_open_prompt_dialog):
# # Test case when password is provided and no matches are found
# main(args=['password123'])
# mock_open_prompt_dialog.assert_not_called()
# mock_get_matches.assert_called_once_with('password123')
# mock_print.assert_called_once_with('This password has not appeared in any data breaches!')

# # Test case when password is provided and matches are found
# mock_get_matches.return_value = 5
# main(args=['password123'])
# mock_get_matches.assert_called_with('password123')
# mock_print.assert_called_with('This password has appeared 5 times in data breaches.')

# # Test case when no password is provided and no matches are found
# mock_get_matches.return_value = None
# main(args=[])
# mock_open_prompt_dialog.assert_called_once()
# mock_get_matches.assert_called_once_with()
# mock_print.assert_called_once_with('This password has not appeared in any data breaches!')

# # Test case when no password is provided and matches are found
# mock_get_matches.return_value = 10
# main(args=[])
# mock_get_matches.assert_called_with()
# mock_print.assert_called_with('This password has appeared 10 times in data breaches.')
