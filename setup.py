#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Setup file for silentdune_client.

    This file was generated with PyScaffold 2.5, a tool that easily
    puts up a scaffold for your new Python project. Learn more under:
    http://pyscaffold.readthedocs.org/
"""

import os
import sys
from setuptools import setup, find_packages

__VERSION__ = "0.6"


def find_package_data_files(dirs):
    paths = []
    for directory in dirs:
        for (path, directories, filenames) in os.walk(directory):
            for filename in filenames:
                paths.append(os.path.join('..', path, filename))
    return paths


def setup_package():

    # Recursively gather all non-python module directories to be included in packaging.
    core_files = find_package_data_files([
        'silentdune_client/init',
        'silentdune_client/selinux',
        'silentdune_client/po',
    ])

    needs_sphinx = set(['build_sphinx', 'upload_docs']).intersection(set(sys.argv))
    sphinx = ['sphinx'] if needs_sphinx else []
    setup(
        name='SilentDune-Client',
        packages=find_packages(exclude=['tests']),
        package_data={
            'silentdune_client': core_files,
        },
        version=__VERSION__,
        description='Silent Dune FPA Client',
        author='Robert Abram',
        author_email='robert.abram@entpack.com',
        maintainer='Robert Abram',
        maintainer_email='robert.abram@entpack.com',
        url='https://github.com/EntPack/SilentDune-Client',
        download_url='https://github.com/EntPack/SilentDune-Client/tarball/0.1',
        keywords=['firewall', 'security'],  # arbitrary keywords
        classifiers=[
            'Development Status :: 4 - Beta',
            'Programming Language :: Python',
            'Environment :: Console',
            'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
            'Operating System :: POSIX :: Linux',
        ],

        install_requires=[
                             'setuptools',
                             # 'requests',
                             # 'cryptography',
                             # 'python-dateutil',
                             # 'dnspython',
                         ] + sphinx,

        tests_require=[
            'pytest',
            'pytest-runner',
            'pytest-pythonpath',
        ],

        entry_points={
            'console_scripts': [
                'sdc-install = silentdune_client.sdc_install:run',
                'sdc-firewall = silentdune_client.sdc_firewall:run',
            ],
        }
    )


if __name__ == "__main__":
    setup_package()
