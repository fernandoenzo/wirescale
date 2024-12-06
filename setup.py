#!/usr/bin/env python3
# encoding:utf-8

import sys
from pathlib import Path

# More on how to configure this file here: https://setuptools.readthedocs.io/en/latest/setuptools.html#metadata
from autopackage.parsers.setup_parser import SetupParser
from setuptools import find_packages

PROGRAM_FOLDER = Path(__file__).parent.joinpath('wirescale').resolve()
sys.path.insert(0, PROGRAM_FOLDER.name)

from version import VERSION

name = 'wirescale'

# https://www.python.org/dev/peps/pep-0440/#version-scheme
version = VERSION

description = ('Wirescale: Secure, Efficient Connectivity. Elevate your network with stable WireGuard tunnels over Tailscale, '
               'enhancing speed and flexibility with customizable configuration.')

with open("README.md", "r") as fh:
    long_description = fh.read()

author = 'Fernando Enzo Guarini'
author_email = 'fernandoenzo@gmail.com'

url = 'https://github.com/fernandoenzo/wirescale/'
download_url = 'https://github.com/fernandoenzo/wirescale/releases/'

# https://packaging.python.org/guides/distributing-packages-using-setuptools/#project-urls
project_urls = {
    'Source': 'https://github.com/fernandoenzo/wirescale/',
}

packages = find_packages()

license = 'AGPLv3+'

zip_safe = True

keywords = 'wireguard tunnel tunneling vpn tailscale secure networking mesh p2p peer-to-peer ip link route routing net internet ping subnet subnetting'

python_requires = '>=3.11'

install_requires = [
    "cryptography == 44.0.0",
    "netifaces == 0.11.0",
    "parallel-utils == 1.3.1",
    "websockets == 14.1",
]

# https://pypi.org/classifiers/
classifiers = [
    'Development Status :: 5 - Production/Stable',
    'Intended Audience :: End Users/Desktop',
    'Intended Audience :: System Administrators',
    'Intended Audience :: Telecommunications Industry',
    'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
    'Natural Language :: English',
    'Operating System :: POSIX :: Linux',
    'Programming Language :: Python :: 3 :: Only',
    'Programming Language :: Python :: 3.11',
    'Programming Language :: Python :: 3.12',
    'Topic :: Communications',
    'Topic :: Internet',
    'Topic :: System :: Networking',
    'Topic :: Utilities'
]

entry_points = {
    'console_scripts': [
        'wirescale = wirescale.wirescale:main',
    ]
}

package_data = {
    'wirescale': [
        'scripts/*',
        'systemd/*',
    ],
}

SetupParser(
    author_email=author_email,
    author=author,
    classifiers=classifiers,
    description=description,
    download_url=download_url,
    entry_points=entry_points,
    install_requires=install_requires,
    keywords=keywords,
    license=license,
    long_description_content_type="text/markdown",
    long_description=long_description,
    name=name,
    package_data=package_data,
    packages=packages,
    python_requires=python_requires,
    url=url,
    version=version,
    zip_safe=zip_safe,
)
