# Phase 2: CA Challenge Walkthrough

## Overview

This phase covers PKI infiltration, Burp Suite MITM, certificate manipulation, and file recovery. Participants must obtain a valid, CA-signed certificate with specific subject fields to authenticate to the server.

## Prerequisites
- Understanding of X.509 certificates and PKI
- Familiarity with CSR (Certificate Signing Request) generation
- Experience with Burp Suite or similar proxy tools
- Basic OpenSSL usage

## Step-by-Step Solution

1. **Analyze the Requirements**
   - The server requires a client certificate signed by its CA, with specific subject fields (e.g., Organization: "Sharif University of Technology", Common Name: your name).
   - The certificate and private key must match.

2. **Generate a CSR with Your Private Key**
```python
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
# Load or generate a private key
with open('client.key', 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)
# Build CSR (fields may need to be modified via Burp Suite)
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "IR"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Tehran"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Tehran"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "None"),  # To be changed
    x509.NameAttribute(NameOID.COMMON_NAME, "None"),        # To be changed
])).sign(private_key, hashes.SHA512())
```

3. **Intercept and Modify the CSR with Burp Suite**
   - Configure your client to use Burp Suite as a proxy (127.0.0.1:8080).
   - Intercept the HTTP POST request containing the CSR.
   - Modify the Organization and Common Name fields to match the server's requirements.
   - Forward the modified request to the CA server.

4. **Download and Recover the Signed Certificate**
   - The server may delete the certificate after download. Use file recovery tools (e.g., Recuva, photorec) if needed.

5. **Verify Certificate and Key Match**
   - Use OpenSSL to check that the certificate and private key are a valid pair:
```powershell
openssl x509 -noout -modulus -in client.crt | openssl md5
openssl rsa -noout -modulus -in client.key | openssl md5
# The hashes must match.
```

6. **Authenticate to the Server**
   - Use the signed certificate and matching key to connect to the server and proceed to the next phase.

## Troubleshooting
- **SSL Handshake Error: peer did not return a certificate**
  - The certificate and key do not match. Regenerate the CSR using the correct private key.
- **Fields not accepted?**
  - Double-check the Organization and Common Name fields in the certificate.
- **File missing?**
  - Use forensic tools to recover deleted files.

## Reference
- See `tls/protocol.py` and `tls/server_challenges/ca_challenge.py` for implementation details.
- Use Burp Suite and OpenSSL as described above.
