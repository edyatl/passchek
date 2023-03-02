#!/usr/bin/env python3
import setuptools

from passchek.passchek import __version__

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="passchek",
    version=__version__,
    license="MIT",
    author="Yevgeny Dyatlov",
    author_email="edyatl@yandex.ru",
    description="Passchek is a simple cli tool, checks if your password has been compromised.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/edyatl/passchek",
    packages=setuptools.find_packages(),
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "passchek=passchek.passchek:main",
        ]
    },
    keywords=[
        "passchek",
        "password",
        "pwned",
        "troyhunt",
        "github",
        "k-anonymity",
        "interactive",
        "console",
        "sha1",
        "pwnedpassword",
        "versions",
        "virtualenv",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Environment :: Console",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX",
        "Intended Audience :: End Users/Desktop",
        "Topic :: Utilities",
    ],
    python_requires=">=3.5",
)
