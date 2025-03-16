from setuptools import setup, find_packages

setup(
    name="tls",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        'cryptography',
        'pyOpenSSL',
    ],
)