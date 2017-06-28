"""setup.py."""


import io
import os
import re
from setuptools import setup, find_packages


# Example code to pull version from esptool.py with regex, taken from
# https://packaging.python.org/guides/single-sourcing-package-version/
def read(*names, **kwargs):
    """Read file."""
    with io.open(
        os.path.join(os.path.dirname(__file__), *names),
        encoding=kwargs.get("encoding", "utf8")
    ) as filp:
        return filp.read()


def find_version(*file_paths):
    """Read .py file and locate version string."""
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


setup(
    name='asterisk_mbox',
    packages=find_packages(),
    version=find_version("asterisk_mbox", "utils.py"),
    description='The client side of a client/server to interact with'
                ' Asterisk voicemail mailboxes',
    long_description=open('README.rst').read(),
    author='PhracturedBlue',
    author_email='rc2012@pblue.org',
    url='https://github.com/PhracturedBlue/asterisk_mbox',
    keywords=['testing', 'asterisk', "mailbox", "voicemail"],
    classifiers=[],
)
