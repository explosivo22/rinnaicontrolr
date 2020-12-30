import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="rinnaicontrol-r",
    version="0.0.1",
    description="Python interface for Rinnai Control-R API",
    url="https://github.com/explosivo22/rinnaicontrol-r",
    author="Brad Barbour",
    author_email="barbourbj@gmail.com",
    license='Apache Software License',
    install_requires=[ 'requests>=2.0' ],
    keywords=[ 'rinnai', 'home automation', 'water heater' ],
    packages=[ 'rinnaicontrol-r' ],
    zip_safe=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
)