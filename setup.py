#!/usr/bin/env python3
import os
from setuptools import setup, find_packages

# Repository name is the module name with dashes, ex. hit-py-template
# Module name can only contain underscores, so hit_py_template
# Also, configure the module under hit_py_template/__version__.py
repository_name = 'sshkey-tools'
module_name = 'sshkey_tools'
python_min_version = ">=3.6"

with open('requirements.txt', 'r') as f:
    required_packages = f.read().splitlines()

# Get key package details
about = {}  # type: ignore
here = os.path.abspath(os.path.dirname(__file__))

# Load the __version__.py file from the plugin directory
with open(os.path.join(here, 'src', module_name, '__version__.py')) as f:
    exec(f.read(), about)

# Load the README file and use it as the long_description for PyPI
with open('README.md', 'r') as f:
    readme = f.read()

# Package configuration - for reference see:
# https://setuptools.readthedocs.io/en/latest/setuptools.html#id9
setup(
    name=about['__title__'],
    description=about['__description__'],
    long_description=readme,
    long_description_content_type='text/markdown',
    version=about['__version__'],
    author=about['__author__'],
    author_email=about['__author_email__'],
    url=about['__url__'],
    packages=find_packages(where="src"),
    include_package_data=True,
    python_requires=python_min_version,
    install_requires=required_packages,
    license=about['__license__'],
    zip_safe=True,
    package_dir={"": "src"},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    keywords='python openssh ssh keys sshkey ssh-keygen ssh-certificate certificate parser decoder',
    entry_points = {
        'console_scripts': [
            'sshkey=sshkey_tools.cli:main'
        ]
    }
)
