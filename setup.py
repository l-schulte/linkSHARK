#!/usr/bin/env python

import sys

from setuptools import setup, find_packages

if not sys.version_info[0] == 3:
    print('only python3 supported!')
    sys.exit(1)

setup(
    name='linkSHARK',
    version='0.1.1',
    description='Issue linking for smartSHARK.',
    install_requires=['mongoengine', 'pymongo', 'pycoshark>=1.0.14', 'numpy', 'pandas', 'nltk', 'scikit-learn'],
    dependency_links=['git+https://github.com/smartshark/pycoSHARK.git@1.0.14#egg=pycoshark-1.0.14'],
    author='sherbold',
    author_email='herbold@cs.uni-goettingen.de',
    url='https://github.com/smartshark/linkSHARK',
    download_url='https://github.com/smartshark/linkSHARK/zipball/master',
    test_suite='linkSHARK.tests',
    packages=find_packages(),
    zip_safe=False,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache2.0 License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
