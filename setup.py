import io
import os

from setuptools import setup

# The text of the README file
here = os.path.abspath(os.path.dirname(__file__))
try:
    with io.open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
        long_description = '\n' + f.read()
except FileNotFoundError:
    long_description = DESCRIPTION

setup(
    name="rinnaicontrolr",
    version="0.4.0",
    description="Python interface for Rinnai Control-R API",
    long_description=long_description,
    long_description_content_type='text/markdown',
    url="https://github.com/explosivo22/rinnaicontrolr",
    author="Brad Barbour",
    author_email="barbourbj@gmail.com",
    license='Apache Software License',
    install_requires=[ 'requests>=2.0', 'boto3>=1.17' ],
    keywords=[ 'rinnai', 'home automation', 'water heater' ],
    packages=[ 'rinnaicontrolr' ],
    zip_safe=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
)
