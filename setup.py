#!/usr/bin/env python

# Adapted from https://github.com/pypa/sampleproject/blob/master/setup.py

# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

# Arguments marked as "Required" below must be included for upload to PyPI.
# Fields marked as "Optional" may be commented out.

setup(
    # Name of project. The first time you publish this
    # package, this name will be registered for you. It will determine how
    # users can install this project, e.g.:
    #
    # $ pip install mudparser
    name='mudparser',  # Required

    # Versions should comply with PEP 440:
    # https://www.python.org/dev/peps/pep-0440/
    version='1.2.0',  # Required

    # This is a one-line description or tagline of what your project does.
    description='A tool for parsing MUD profiles.',  # Required

    # This is an optional longer description of your project that represents
    # the body of text which users will see when they visit PyPI.
    long_description=long_description,  # Optional

    # Denotes that our long_description is in Markdown; valid values are
    # text/plain, text/x-rst, and text/markdown
    #
    # Optional if long_description is written in reStructuredText (rst) but
    # required for plain-text or Markdown; if unspecified, "applications should
    # attempt to render [the long_description] as text/x-rst; charset=UTF-8 and
    # fall back to text/plain if it is not valid rst" (see link below)
    long_description_content_type='text/markdown',  # Optional (see note above)

    # This should be a valid link to your project's main homepage.
    #
    # This field corresponds to the "Home-Page" metadata field:
    # https://packaging.python.org/specifications/core-metadata/#home-page-optional
    url='https://github.com/elmiomar/mudsdn',  # Optional

    author='Omar I. EL MIMOUNI',  # Optional

    author_email='omarilias.elmimouni@nist.gov',  # Optional

    classifiers=[  # Optional
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 3 - Alpha',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',

        # Pick your license as you wish
        'License :: OSI Approved :: MIT License',

        # Python version supported
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],

    # Project keywords
    keywords='mud sdn iot parser acl security',  # Optional

    # Packages to be installed. If a single Python file, use
    # the `py_modules` argument instead as follows, which will expect a file
    # called `my_module.py` to exist:
    #
    #   py_modules=["my_module"],
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),  # Required

    # List of other packages that this project depends on to run.
    # install_requires=[],  # Optional

    # Extra dependencies. Users will be able to install these using the "extras"
    # syntax, for example:
    #
    #   $ pip install mudparser[dev]
    # extras_require={  # Optional
    #     'dev': ['check-manifest'],
    #     'test': ['coverage'],
    # },

    # If there are data files included in your packages that need to be
    # installed, specify them here.
    # package_data={  # Optional
    #     'sample': ['package_data.dat'],
    # },

    # If data files are placed outside of package folder.
    # In this case, 'data_file' will be installed into '<sys.prefix>/my_data'
    data_files=[('my_data', ['data/amazon_echo_short.json'])],  # Optional

    # To provide executable scripts, use entry points in preference to the
    # "scripts" keyword. Entry points provide cross-platform support and allow
    # `pip` to create the appropriate form of executable for the target
    # platform.
    #
    # For example, the following would provide a command called `sample` which
    # executes the function `main` from this package when invoked:
    entry_points={  # Optional
        'console_scripts': [
            'parse=mudparser:main',
        ],
    },

    # List additional URLs that are relevant to your project as a dict.
    project_urls={  # Optional
        'Issues': 'https://github.com/elmiomar/mudparser/issues',
        'Source': 'https://github.com/elmiomar/mudparser/',
    },
)