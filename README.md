# Communication CTF Challenge

This project implements a network security challenge focusing on SSL certificate handling and client authentication. It consists of two main components: a Certificate Authority (CA) server and a main server requiring client certificate authentication.

## Project Structure

```
communication/
├── README.md
├── client_server/          # Main server implementation
│   ├── client/
│   │   └── advanced_client.py
│   ├── server/
│   │   ├── server.py
│   │   ├── server_utils.py
│   │   └── base64_picture.py
│   └── shared/
│       └── protocol.py
│
└── csr_ca/                # Certificate Authority implementation
    ├── client/
    │   ├── csr_client.py
    │   └── csr_client_utils.py
    ├── server/
    │   ├── ca_server.py
    │   └── ca_server_utils.py
    └── shared/
        └── protocol.py
```

## Components

### 1. Certificate Authority (CA) Server
Located in `csr_ca/server/`, the CA server is responsible for:
- Creating and managing the Certificate Authority
- Managing CA certificates and keys (`ca.crt`, `ca.key`)
- Processing Certificate Signing Requests (CSRs) from clients
- Validating CSR authenticity and format
- Signing valid CSRs with the CA's private key
- Returning signed certificates to clients

### 2. Main Server
Located in `client_server/server/`, this server implements:
- Strict client certificate authentication
- Certificate validation against the CA
- Encrypted communication with authenticated clients
- Custom response handling for validated requests

### 3. Utilities and Shared Components
- SSL/TLS utilities for certificate operations
- Protocol configurations for both servers
- Network communication utilities
- Shared constants and configurations

## Challenge Flow

1. **Initial Connection**
   - Client attempts to connect to main server
   - Connection fails due to missing valid certificate

2. **Certificate Acquisition**
   - Client discovers CA server's presence
   - Client generates Certificate Signing Request (CSR)
   - CA server processes and signs the CSR
   - Client receives signed certificate

3. **Authenticated Connection**
   - Client connects to main server using signed certificate
   - Server validates certificate against CA
   - Server provides encrypted response upon successful authentication

## Getting Started

### Prerequisites
- Python 3.8+
- Required Python packages:
  - cryptography
  - pyOpenSSL

### Running the Servers
1. Start the CA Server:
```bash
python csr_ca/server/ca_server.py
```

2. Start the Main Server:
```bash
python client_server/server/server.py
```

### Client Connection
Basic client connection example:
```bash
python client_server/client/advanced_client.py
```

## Security Note
This is a CTF challenge implementation - not intended for production use. Certificates and keys are embedded in the code for challenge purposes.

## Challenge Objective
Participants need to:
1. Understand the certificate-based authentication system
2. Generate valid CSRs for the CA
3. Obtain signed certificates
4. Successfully authenticate with the main server

## Additional Resources
- OpenSSL documentation for CSR generation
- SSL/TLS protocol specifications
- Python `ssl` and `cryptography` module documentation