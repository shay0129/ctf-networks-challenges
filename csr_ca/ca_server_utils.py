"""
Certificate Authority Server Utilities
Provides functions for SSL certificate operations, CSR handling, and HTTP parsing.
"""

from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.backends import default_backend

from cryptography import x509
from OpenSSL import crypto
from typing import Tuple, Optional, Dict, Union
from socket import socket
import traceback
import tempfile
import random
import ssl
import logging

from protocol import ProtocolConfig

# Certificate Operations
def create_csr(country: str, state: str, city: str, org_name: str, 
               org_unit: str, domain_name: str) -> Tuple[bytes, bytes]:
    """
    Create a Certificate Signing Request (CSR) and private key.

    Args:
        country: Country code (e.g., 'US')
        state: State or province
        city: City or locality
        org_name: Organization name
        org_unit: Organizational unit name
        domain_name: Common name (domain name)

    Returns:
        Tuple containing CSR and private key in PEM format
    """
    private_key = crypto.PKey()
    private_key.generate_key(crypto.TYPE_RSA, 4096)

    csr = crypto.X509Req()
    subject = csr.get_subject()
    subject.C = country
    subject.ST = state
    subject.L = city
    subject.O = org_name
    subject.OU = org_unit
    subject.CN = domain_name

    csr.set_pubkey(private_key)
    csr.sign(private_key, 'sha512')

    csr_pem = crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr)
    private_key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key)

    return csr_pem, private_key_pem

def create_ca_server_ssl_context(cert: bytes, key: bytes) -> ssl.SSLContext:
    """
    Create and configure SSL context for CA server.

    Args:
        cert: Certificate data in PEM format
        key: Private key data in PEM format

    Returns:
        Configured SSL context
    """
    cert_bytes = cert.encode() if isinstance(cert, str) else cert
    key_bytes = key.encode() if isinstance(key, str) else key

    with tempfile.NamedTemporaryFile(delete=False) as cert_file, \
         tempfile.NamedTemporaryFile(delete=False) as key_file:
        cert_file.write(cert_bytes)
        key_file.write(key_bytes)
        cert_path, key_path = cert_file.name, key_file.name

    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.set_ciphers("AES128-SHA256")
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)

    return context

def sign_csr_with_ca(csr_pem: bytes, ca_key_pem: bytes = None, 
                     ca_cert_pem: bytes = None) -> Optional[bytes]:
    """
    Sign a CSR using CA's private key.

    Args:
        csr_pem: CSR in PEM format
        ca_key_pem: CA private key in PEM format
        ca_cert_pem: CA certificate in PEM format (optional for self-signing)

    Returns:
        Signed certificate in PEM format
    """
    try:
        csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_pem)
        cert = crypto.X509()
        cert.set_subject(csr.get_subject())
        cert.set_pubkey(csr.get_pubkey())
        cert.set_serial_number(random.getrandbits(64))
        
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(31536000)  # 1 year

        if ca_cert_pem:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_pem)
            cert.set_issuer(ca_cert.get_subject())
        else:
            cert.set_issuer(csr.get_subject())

        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_key_pem)
        cert.sign(ca_key, 'sha512')

        return crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    except Exception as e:
        logging.error(f"Error signing CSR: {e}")
        return None

# File Operations
def download_file(file_name: str, content: Union[str, bytes]) -> None:
    """
    Save content to file with automatic encoding handling.

    Args:
        file_name: Target file path
        content: Content to save (string or bytes)
    """
    with open(file_name, "wb") as f:
        if isinstance(content, str):
            f.write(content.encode())
        else:
            f.write(content)
    logging.info(f"File saved to {file_name}")

# Validation Functions
def verify_client_csr(csr_data: bytes) -> Optional[crypto.X509Req]:
    """
    Verify CSR signature and format.

    Args:
        csr_data: CSR data in PEM format

    Returns:
        Verified CSR object or None if invalid
    """
    try:
        if not csr_data.startswith(b"-----BEGIN CERTIFICATE REQUEST-----"):
            logging.error("Invalid CSR format")
            return None
            
        csr_obj = x509.load_pem_x509_csr(csr_data, default_backend())
        csr_obj.public_key().verify(
            csr_obj.signature,
            csr_obj.tbs_certrequest_bytes,
            asymmetric_padding.PKCS1v15(),
            csr_obj.signature_hash_algorithm,
        )
        
        logging.info("CSR verification successful")
        return csr_obj
    except Exception as e:
        logging.error(f"CSR verification failed: {e}")
        return None

def validate_certificate(cert_data: bytes) -> bool:
    """
    Validate certificate PEM format.

    Args:
        cert_data: Certificate data to validate

    Returns:
        True if valid PEM format, False otherwise
    """
    return (cert_data.startswith(b"-----BEGIN CERTIFICATE-----") and 
            cert_data.endswith(b"-----END CERTIFICATE-----\n"))

def parse_http_headers(raw_data: bytes) -> Tuple[Optional[Dict[bytes, bytes]], bytes, Optional[int]]:
    """
    Parse HTTP headers from raw data.

    Args:
        raw_data: Raw HTTP request/response data

    Returns:
        Tuple containing:
        - Dictionary of headers (or None if parsing fails)
        - Body content in bytes  # היה כתוב רק "Body content"
        - Content length if specified (or None)
    """
    try:
        header_part, body = raw_data.split(b'\r\n\r\n', 1)
        header_lines = header_part.split(b'\r\n')
        headers = {}

        for line in header_lines[1:]:
            if b':' in line:
                key, value = line.split(b':', 1)
                headers[key.strip().lower()] = value.strip()

        content_length = None
        if b'content-length' in headers:
            try:
                content_length = int(headers[b'content-length'])
            except ValueError:
                pass

        return headers, body, content_length
    except Exception as e:
        logging.error(f"Error parsing HTTP headers: {e}")
        return None, b"", None

def parse_http_request(data: bytes) -> Tuple[Optional[Dict[bytes, bytes]], Optional[bytes]]:
    """
    Parse HTTP request data into headers and body.

    Args:
        data: Raw HTTP request data

    Returns:
        Tuple containing:
        - Dictionary of headers including request line components
        - Request body content
    """
    try:
        headers_raw, body = data.split(b'\r\n\r\n', 1)
        header_lines = headers_raw.split(b'\r\n')
        
        request_method, request_path, request_version = header_lines[0].split(b' ', 2)
        headers = {
            b'request_method': request_method,
            b'request_path': request_path,
            b'request_version': request_version
        }
        
        for line in header_lines[1:]:
            if b':' in line:
                key, value = line.split(b':', 1)
                headers[key.strip().lower()] = value.strip()
        
        return headers, body
    except Exception as e:
        logging.error(f"Error parsing HTTP request: {e}")
        traceback.print_exc()
        return None, None

def format_error_response(status_line: bytes, error_msg: Union[str, bytes]) -> bytes:
    """
    Create properly formatted HTTP error response.

    Args:
        status_line: HTTP status line (e.g., b"HTTP/1.1 400 Bad Request")
        error_msg: Error message content

    Returns:
        Complete HTTP response as bytes
    """
    error_msg_bytes = error_msg.encode('utf-8') if isinstance(error_msg, str) else error_msg
    content_length = str(len(error_msg_bytes)).encode('utf-8')
    
    response = [
        status_line,
        b"Content-Type: text/plain",
        b"Content-Length: " + content_length,
        b"Connection: close",
        b"",
        b""
    ]
    
    return b"\r\n".join(response) + error_msg_bytes

def receive_all(sock: socket, expected_length: Optional[int] = None) -> bytes:
    """
    Receive all data from socket until completion or expected length.

    Args:
        sock: Socket to receive data from
        expected_length: Expected content length (optional)

    Returns:
        Received data as bytes
    """
    data = b""
    while True:
        chunk = sock.recv(ProtocolConfig.MAX_MSG_LENGTH)
        if not chunk:
            break
        data += chunk
        if expected_length and len(data) >= expected_length:
            break
    return data

def monitor_content_length(actual_size: int, declared_size: int, source: str, direction: str) -> None:
    """
    Monitor and log content length differences.
    
    Args:
        actual_size: Actual content size in bytes
        declared_size: Declared Content-Length value
        source: Source identifier ('CLIENT' or 'SERVER')
        direction: Direction identifier ('SENT' or 'RECEIVED')
    """
    logging.info(f"\n=== Content Length Monitor ===")
    logging.info(f"Source: {source}")
    logging.info(f"Direction: {direction}")
    logging.info(f"Declared Content-Length: {declared_size}")
    logging.info(f"Actual Size: {actual_size}")
    
    if actual_size != declared_size:
        logging.warning(f"Size mismatch! Difference: {actual_size - declared_size} bytes")
    else:
        logging.info("Status: MATCH")