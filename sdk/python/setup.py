"""CryptoServe SDK setup."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="cryptoserve",
    version="0.2.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.28.0",
    ],
    extras_require={
        "fastapi": [
            "pydantic>=2.0.0",
        ],
        "sqlalchemy": [
            "sqlalchemy>=2.0.0",
        ],
        "all": [
            "pydantic>=2.0.0",
            "sqlalchemy>=2.0.0",
        ],
    },
    python_requires=">=3.9",
    author="CryptoServe",
    author_email="",
    description="CryptoServe SDK - Zero-config cryptographic operations",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/cryptoserve",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
    ],
    keywords="cryptography, encryption, security, sdk",
)
