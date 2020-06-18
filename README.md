![Passchek logo](https://svgshare.com/i/Lwy.svg)


# Passchek


> Passchek is a simple cli tool, checks if your password has been compromised.

[![Version: v0.2](https://img.shields.io/badge/version-v0.2.1-blue)](https://github.com/edyatl/passchek)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](https://github.com/edyatl/passchek/LICENSE)
[![Python3](https://img.shields.io/badge/python-3.5%20%7C%203.6%20%7C%203.7-blue)](https://github.com/edyatl/passchek)

Passchek is a python program for searching in [Troy Hunt's pwnedpassword](https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/) API using the k-anonymity algorithm. 

Passchek was inspired by [jamesridgway](https://github.com/jamesridgway)/[pwnedpasswords.sh](https://github.com/jamesridgway/pwnedpasswords.sh) bash script.


## Algorithm


1. Hash the PASSWORD by SHA1.
2. Split hash for 5 char prefix and 35 char suffix.
3. Requests [Troy Hunt's pwnedpassword](https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/) API for the prefix.
4. Convert response to the dictionary with suffixes as keys and number of matches as values.
5. And finally determine matches for initial PASSWORD by its hash suffix as a key.


## Features


- Checks one password or number of passwords.
- Shows a text sentence about  compromising or just figures.
- It can be used in shell pipes, it can read stdin.
- It can display the SHA1 password hash in a tuple format (“prefix”, “suffix”) without an Internet request.


## Usage


```sh
    Usage:
        passchek.py [options] [<PASSWORD>]

    Arguments:
        PASSWORD Provide (password | passwords) as argument or leave blank to provide via stdin or prompt

    Options:
        -h, --help      Shows this help message and exit
        -n, --num-only  Set output without accompanying text
        -p, --pipe      For use in shell pipes, read stdin
        -s, --sha1      Shows SHA1 hash in tuple ("prefix", "suffix") and exit
        -v, --version   Shows current version of the program and exit
```

### Security Note

Please note that in case of using PASSWORD as command line argument it will be kept in .bash_history file in raw insecure format. Using via explicit prompt dialog is more secure and preferably.


## Usage examples


A) Call **passchek** without options and arguments, enter 'qwerty' as an example password. *Please note that when you are typing password via explicit prompt, nothing is displayed on the screen, this is normal and is used for security reasons.* After press Enter key you'll see a sentence in new line with number of matches in the pwnedpassword DB.

```sh
    $ python3 passchek.py 
    Enter password: 
    This password has appeared 3912816 times in data breaches.
```

B) Call **passchek** with option '-n' (--num-only) without arguments, enter 'qwerty' as an example password. After press Enter key you'll see a number in new line with matches in the pwnedpassword DB.

```sh
    $ python3 passchek.py -n 
    Enter password: 
    3912816
```

C) Call **passchek** with option '-s' (--sha1) without arguments, enter 'qwerty' as an example password. After press Enter key you'll see new line with the password hash in a tuple format (“prefix”, “suffix”).

```sh
    $ python3 passchek.py -s
    Enter password: 
    ('B1B37', '73A05C0ED0176787A4F1574FF0075F7521E')
```

D) Call **passchek** with options '-ns' (--num-only --sha1) without arguments, enter 'qwerty' as an example password. After press Enter key you'll see new line with the password hash splited by space 'prefix suffix'.

```sh
    $ python3 passchek.py -ns
    Enter password: 
    B1B37 73A05C0ED0176787A4F1574FF0075F7521E
```

E) Call **passchek** without options and with argument 'qwerty' as an example password. You'll see a sentence in new line with number of matches in the pwnedpassword DB. *Please note that using real password as an argument not recommended, for more details see [Security Note](#security-note).*

```sh
    $ python3 passchek.py qwerty
    This password has appeared 3912816 times in data breaches.
```

F) Call **passchek** with option '-n' (--num-only) and with arguments 'qwerty', 'ytrewq', 'qazwsx' *(these three are very common weak passwords)* and 'jnfjdfksdjfbskjdeuhiseg' *(random typing)* as examples passwords. You'll see numbers in new lines with matches in the pwnedpassword DB. *Please don't forget about [Security Note](#security-note).*

```sh
    $ python3 passchek.py -n qwerty ytrewq qazwsx jnfjdfksdjfbskjdeuhiseg
    3912816
    33338
    505344
    0
```

G) Use **passchek** with options '-np' (--num-only --pipe) in pipe with `cat pass_list.txt` to check all passwords in text file (In this example text file was created as `ls .. > pass_list.txt` in the script dir). You'll see numbers in new lines with matches in the pwnedpassword DB. 

```sh
    $ cat pass_list.txt | python3 passchek.py -np
    21
    8
    0
    0
    0
    0
    0
    0
    457
```

H) Let's count a number of compromised passwords in the previous example 'G'. 

```sh
    $ cat pass_list.txt | python3 passchek.py -np | grep -v '^0' | wc -l
    3
```
So three passwords in our list have been compromised.

I) To determine these three weak passwords we need to know their line numbers in the text file.

```sh
    $ cat pass_list.txt | python3 passchek.py -np | grep -vn '^0'
    1:21
    2:8
    9:457
```

J) Now we can get a list of strong passwords just delete lines with compromised.

```sh
    $ sed -i '1d;2d;9d;' pass_list.txt | python3 passchek.py -np | grep -v '^0' | wc -l
    0
```
So no more weak passwords detected.


## Installation

You can simple download one script file [passchek.py](./passchek/passchek.py) and use it with python3.

Or try to install by pip.

First check if package exists:

```sh
    $ python3 -m pip search passchek
```
Install if package exists:

```sh
    $ python3 -m pip install --user passchek
```
Or just:
```sh
    $ pip3 install passchek
```


## Help


For help screen just provide `-h` or `--help` as a command line option.

Option `-v` or `--version` shows current version.


## Contributing


The main repository if the code is at https://github.com/edyatl/passchek

I'm happy to take from you any patches, pull requests,  bug reports,  ideas about new functionality and so on.


## Thanks


Thanks to [Troy Hunt](https://www.troyhunt.com) for collecting data and providing API.

Thanks to [James Ridgway](https://github.com/jamesridgway) for [pwnedpasswords.sh](https://github.com/jamesridgway/pwnedpasswords.sh) bash script.


## Authors


Yevgeny Dyatlov ([@edyatl](https://github.com/edyatl))


## License


This project is licensed under the MIT License.

Copyright (c) 2020 Yevgeny Dyatlov ([@edyatl](https://github.com/edyatl))

Please see the [LICENSE](LICENSE) file for details.
