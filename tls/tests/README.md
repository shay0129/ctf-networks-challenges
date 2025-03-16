tests/
├── __init__.py
├── test_files/
│   ├── certificates/
│   │   ├── ca/
│   │   │   ├── ca.key         # CA private key
│   │   │   └── ca.crt         # CA certificate
│   │   ├── valid/
│   │   │   ├── client.key     # Valid client key
│   │   │   ├── client.crt     # Valid CA-signed certificate
│   │   │   └── client.csr     # Valid CSR example
│   │   ├── invalid/
│   │   │   ├── unsigned.crt   # Certificate not signed by CA
│   │   │   ├── wrong_country.crt  # Certificate with wrong country
│   │   │   └── mitm.crt       # MITM certificate example
│   │   └── README.md          # Certificate details and generation instructions
│   ├── payloads/
│   │   ├── valid_csr.pem      # Valid CSR content
│   │   ├── invalid_csr.pem    # Malformed CSR
│   │   └── missing_fields.pem # CSR with missing required fields
│   └── images/
│       ├── test_image.png     # Test image for embedding
│       └── embedded_key.png   # Image with embedded key
├── test_ca.py                 # CA server tests
├── test_server.py             # Main server tests
├── test_icmp.py               # ICMP challenge tests
├── test_image.py              # Image challenge tests
├── test_utils.py              # Utility function tests
├── conftest.py                # pytest configurations
└── README.md                  # Testing documentation

# Testing Documentation

This directory contains the test suite for the CTF server and its components. Below is a brief description of each file and directory:

- `__init__.py`: Marks the directory as a Python package.
- `test_files/`: Contains test data files used in the tests.
  - `certificates/`: Contains various certificates used for testing.
    - `ca/`: Contains the CA certificate and key.
    - `valid/`: Contains valid certificates and CSRs.
    - `invalid/`: Contains invalid certificates for testing rejection scenarios.
    - `README.md`: Instructions for generating and details about the certificates.
  - `payloads/`: Contains CSR payloads for testing.
  - `images/`: Contains images used in the image challenge tests.
- `test_ca.py`: Contains tests for the CA server functionality.
- `test_server.py`: Contains tests for the main CTF server.
- `test_icmp.py`: Contains tests for the ICMP challenge.
- `test_image.py`: Contains tests for the image challenge.
- `test_utils.py`: Contains tests for utility functions.
- `conftest.py`: Contains pytest configurations and custom markers.
- `README.md`: This documentation file.