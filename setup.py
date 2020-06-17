#!/usr/bin/env python3
import setuptools

from passchek.passchek import __version__

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="passchek",
    version=__version__,
    author="Yevgeny Dyatlov",
    author_email="edyatl@yandex.ru",
    description="Passchek is a simple cli tool, checks if your password has been compromised.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/edyatl/passchek",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX",
    ],
    python_requires='>=3.5',
)
