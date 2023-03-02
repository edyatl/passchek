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


__version__ = "0.2.2"


def usage():
    """Show usage help screen and exit."""
    usg_text = """    Passchek is a simple cli tool, checks if your password has been compromised.
    
    Usage:
        {} [options] [<PASSWORD>]

    Arguments:
        PASSWORD Provide (password | passwords) as argument or leave blank to provide via stdin or prompt

    Options:
        -h, --help      Shows this help message and exit
        -n, --num-only  Set output without accompanying text
        -p, --pipe      For use in shell pipes, read stdin
        -s, --sha1      Shows SHA1 hash in tuple ('prefix', 'suffix') and exit
        -v, --version   Shows current version of the program and exit
    """
    print(usg_text.format(os.path.basename(__file__)))


def hash_password(raw_pass):
    """Hashing raw password and split hash to prefix and suffix.

    :param raw_pass: password in raw format
    :return: tuple (prefix of hash, suffix of hash)
    """
    raw_pass = raw_pass if raw_pass else ""
    hash_pass = hashlib.sha1(raw_pass.encode("utf8")).hexdigest().upper()
    hash_pass_prefix = hash_pass[:5]
    hash_pass_suffix = hash_pass[5:]
    return hash_pass_prefix, hash_pass_suffix


def open_prompt_dialog():
    """Open prompt dialog for enter password.

    :return: result tuple of hash_password (prefix of hash, suffix of hash)
    """
    raw_pass = getpass.getpass("Enter password: ")
    return hash_password(raw_pass)


def url_join(*url_parts):
    """Join parts of url.

    :param url_parts: path + prefix of password hash
    :return: complete url string
    """
    return "https://api.pwnedpasswords.com/" + "/".join(url_parts)


def reqst(*url_parts):
    """Make request to Troy Hunt's pwnedpassword API.

    :param url_parts: path + prefix of password hash
    :return: response string of Troy Hunt's pwnedpassword API
    """
    pwnd_url = url_join(*url_parts)
    req = urllib.request.Request(
        url=pwnd_url,
        headers={
            "User-Agent": "passchek " + __version__ + " (Python)",
            "Add - Padding": "true",
        },
    )
    try:
        with urllib.request.urlopen(req) as res:
            response = res.read()
    except (urllib.error.HTTPError, urllib.error.URLError) as err:
        print("Exception found: {}".format(err))
        sys.exit()
    else:
        return response.decode("utf-8-sig")


def convert_key_val_tpl(line):
    """Convert response line from string to key, value tuple.

    :param line: string line from response 'hash_suffix:n_matches'
    :return: key value tuple ('hash_suffix', int)
    """
    _hash, count = line.split(":") if ":" in line else ("0", "0")
    return _hash, int(count)


def get_matches(text_output=None, passwrd=None):
    """Get matches from pwnedpassword DB and show on screen.

    :param passwrd: password in raw format
    :return: prints result of matches
    """
    if passwrd:
        hash_pass = hash_password(passwrd)
    else:
        hash_pass = open_prompt_dialog()

    matches = reqst("range", hash_pass[0])
    matches = dict(map(convert_key_val_tpl, matches.split("\r\n")))
    matches = matches.get(hash_pass[1])

    if text_output:
        matches_txt = "This password has appeared %s times in data breaches."
        not_matches_txt = "This password has not appeared in any data breaches!"
    else:
        matches_txt = "%s"
        not_matches_txt = "0"

    return print(matches_txt % matches) if matches else print(not_matches_txt)


def handle_sha1_option(text_output, use_in_pipe, args):
    """Handle the --sha1 option."""
    if args:
        for _arg in args:
            if text_output:
                print(hash_password(_arg))
            else:
                print(*hash_password(_arg))
        sys.exit()
    elif use_in_pipe:
        for pass_line in sys.stdin.readlines():
            if text_output:
                sys.stdout.write("%s\n" % str(hash_password(pass_line.strip())))
            else:
                sys.stdout.write("%s\n" % " ".join(hash_password(pass_line.strip())))
        sys.exit()
    else:
        if text_output:
            print(open_prompt_dialog())
        else:
            print(*open_prompt_dialog())
        sys.exit()


def main():
    """Define entry point of program."""
    # Set default flags for options
    text_output = True  # --num-only
    use_in_pipe = False  # --pipe
    sha1_output = False  # --sha1

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
