#!/usr/bin/env python3
"""
Setup script for CTF Networks Challenges
A multi-stage CTF challenge focused on network security, TLS protocol, 
certificate management, and encrypted communication analysis.
"""

from setuptools import setup, find_packages
import os

# Read the README file for long description
def read_readme():
    """Read README.md for long description."""
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    try:
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return "CTF Networks Challenges - TLS Handshake, Certificate Authority, and Encryption"

# Read requirements from requirements.txt
def read_requirements():
    """Read requirements from requirements.txt."""
    requirements_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    try:
        with open(requirements_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            # Filter out comments and empty lines, extract package names
            requirements = []
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    requirements.append(line)
            return requirements
    except FileNotFoundError:
        # Fallback to hardcoded requirements
        return [
            'cryptography>=41.0.0',
            'pyOpenSSL>=23.0.0',
            'scapy>=2.5.0',
            'psutil>=5.9.0'
        ]

setup(
    # Basic package information
    name="ctf-networks-challenges",
    version="1.0.0",
    author="CTF Challenge Team",
    author_email="",
    description="Multi-stage CTF challenge focused on network security, TLS protocol, and encryption",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/shay0129/ctf-networks-challenges",
    
    # Package discovery
    packages=find_packages(),
    include_package_data=True,
    
    # Package data
    package_data={
        'tls': [
            'ca.crt',
        ],
        'certificates': [
            '*.crt',
            '*.key',
        ],
        'documents': [
            '*.png',
            '*.gif',
            '*.ico',
        ],
        'music': [
            '*.mp3',
        ],
    },
    
    # Dependencies
    install_requires=read_requirements(),
    
    # Optional dependencies
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-cov>=4.0.0',
            'black>=23.0.0',
            'flake8>=6.0.0',
        ],
        'gui': [
            'psutil>=5.9.0',
        ],
    },
    
    # Python version requirement
    python_requires='>=3.8',
      # Entry points for command-line scripts
    entry_points={
        'console_scripts': [
            'ctf-server=tls.ctf_server:main',
            'ctf-gui=tls.gui:main',
            'ctf-ca-client=tls.ca_client:main',
            'ctf-server-client=tls.server_client:main',
            'ctf-ping-player=tls.server_challenges.ping_player:main',
        ],
    },
    
    # Classification
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Education",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Education",
        "Topic :: System :: Networking",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Environment :: Win32 (MS Windows)",
        "Environment :: X11 Applications",
    ],
    
    # Keywords for search
    keywords=[
        "ctf", "cybersecurity", "tls", "ssl", "cryptography", 
        "networking", "certificate-authority", "icmp", "enigma",
        "penetration-testing", "security-challenge", "education"
    ],
    
    # Project URLs
    project_urls={
        "Bug Reports": "https://github.com/shay0129/ctf-networks-challenges/issues",
        "Source": "https://github.com/shay0129/ctf-networks-challenges",
        "Documentation": "https://github.com/shay0129/ctf-networks-challenges/blob/main/README.md",
        "Related Project": "https://github.com/shay0129/scapy-tls-pcap-creator",
    },
    
    # License
    license="MIT",
    
    # Zip safe
    zip_safe=False,
)
