from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography import x509

from OpenSSL import crypto
from typing import Tuple
import traceback
import datetime
import tempfile
import random
import ssl

from protocol import ProtocolConfig, ClientConfig


from OpenSSL import crypto
import random
from typing import Tuple

def create_csr(country: str, state: str, city: str, org_name: str, org_unit: str, domain_name: str) -> Tuple[bytes, bytes]:
    """
    Creates a Certificate Signing Request (CSR) and private key.
    Returns the CSR and private key in PEM format as bytes.

    Parameters:
    - country: Country code (e.g., 'US')
    - state: State or province
    - city: City or locality
    - org_name: Organization name
    - org_unit: Organizational unit name
    - domain_name: Common name (e.g., domain name)
    
    Returns:
    - A tuple containing the CSR and private key in PEM format as bytes
    """
    # Generate RSA private key for the CSR
    private_key = crypto.PKey()
    private_key.generate_key(crypto.TYPE_RSA, 4096)

    # Create the CSR
    csr = crypto.X509Req()

    # Set CSR subject details
    subject = csr.get_subject()
    subject.C = country
    subject.ST = state
    subject.L = city
    subject.O = org_name
    subject.OU = org_unit
    subject.CN = domain_name

    # Set the public key for the CSR
    csr.set_pubkey(private_key)

    # Sign the CSR with the private key (self-signing here)
    csr.sign(private_key, 'sha512')

    # Convert CSR and private key to PEM format
    csr_pem = crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr)
    private_key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key)

    # Return the CSR and private key as PEM-formatted bytes
    return csr_pem, private_key_pem


def create_ca_server_ssl_context(cert, key) -> ssl.SSLContext:
    """Create and configure the server's SSL context."""

    # Convert strings to bytes if needed
    cert_bytes = cert.encode() if isinstance(cert, str) else cert
    key_bytes = key.encode() if isinstance(key, str) else key

    # Create temporary files for the certificate and key
    with tempfile.NamedTemporaryFile(delete=False) as cert_file:
        cert_file.write(cert_bytes)
        cert_file_path = cert_file.name

    with tempfile.NamedTemporaryFile(delete=False) as key_file:
        key_file.write(key_bytes)
        key_file_path = key_file.name

    # Create an SSL context for the server
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.set_ciphers("AES128-SHA256")
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    # Load the certificate and key into the context
    context.load_cert_chain(certfile=cert_file_path, keyfile=key_file_path)
    
    return context

def sign_csr_with_ca(csr_pem: bytes, ca_key_pem: bytes = None, ca_cert_pem: bytes = None) -> bytes:
    """
    Signs a CSR using the CA's private key.
    Can work in two modes:
    - With ca_cert_pem (signing for another CSR)
    - Without ca_cert_pem (self-signing for a CA's CSR)

    Returns the signed certificate in PEM format.

    Parameters:
    - csr_pem: The CSR to be signed in PEM format
    - ca_cert_pem: The CA certificate in PEM format (optional, defaults to None)
    - ca_key_pem: The CA private key in PEM format
    
    Returns:
    - The signed certificate in PEM format as bytes
    """
    # Load the CSR
    csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_pem)

    # Create a new certificate to sign the CSR
    cert = crypto.X509()

    # Set the certificate subject to be the CSR subject
    cert.set_subject(csr.get_subject())

    # Set the public key from the CSR
    cert.set_pubkey(csr.get_pubkey())

    # Set the serial number for the certificate
    cert.set_serial_number(random.getrandbits(64))

    # Set the validity period (e.g., 1 year)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(31536000)  # 1 year in seconds

    # Set the issuer (if ca_cert_pem is provided, use it; else, self-sign)
    if ca_cert_pem:
        # Load CA certificate to get the issuer information
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_pem)
        cert.set_issuer(ca_cert.get_subject())
    else:
        # Self-signing: the issuer is the same as the subject
        cert.set_issuer(csr.get_subject())

    # Load the CA's private key to sign the certificate
    ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_key_pem)
    cert.sign(ca_key, 'sha512')

    # Convert the signed certificate to PEM format
    signed_cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

    # Return the signed certificate in PEM format
    return signed_cert_pem


def verify_client_csr(csr_data: bytes) -> crypto.X509Req:
    try:
        if not csr_data.startswith(b"-----BEGIN CERTIFICATE REQUEST-----"):
            print("Invalid CSR format")
            return None
            
        csr_obj = x509.load_pem_x509_csr(csr_data, default_backend())
        csr_obj = x509.load_pem_x509_csr(csr_data, default_backend())

        # Verify signature on CSR
        csr_obj.public_key().verify(
            csr_obj.signature,
            csr_obj.tbs_certrequest_bytes,
            asymmetric_padding.PKCS1v15(),
            csr_obj.signature_hash_algorithm,
        )

        # Validate that the CN matches the expected value
        subject = csr_obj.subject
        for attribute in subject:
            if attribute.oid == x509.NameOID.COMMON_NAME:
                if attribute.value != ClientConfig.HOSTNAME:
                    raise ValueError("CSR Common Name does not match expected value.")

        print("CSR verification successful.")
        return csr_obj
    except Exception as e:
        print(f"CSR verification failed: {e}")
        return None

from typing import Tuple, Optional, Dict

def parse_http_headers(raw_data: bytes) -> Tuple[Optional[Dict[bytes, bytes]], str, Optional[int]]:
    try:
        # פיצול לפי \r\n\r\n כדי להפריד את ההדרים מהגוף
        header_part, body_part = raw_data.split(b'\r\n\r\n', 1)
        
        # פיצול השורות של ההדרים
        header_lines = header_part.split(b'\r\n')
        
        # הפקת השורה הראשונה - ה-Request-Line
        request_line = header_lines[0]
        headers = {}
        
        # עיבוד יתר השורות כדי להפיק את ההדרים
        for line in header_lines[1:]:
            if b':' in line:
                key, value = line.split(b':', 1)
                headers[key.strip().lower()] = value.strip()
        
        # הפקת Content-Length אם קיים
        content_length = int(headers.get(b'content-length', b'0'))
        
        return headers, body_part.decode('utf-8', errors='replace'), content_length
    
    except Exception as e:
        print(f"Error parsing HTTP headers: {e}")
        return None, "", None


def parse_http_request(data):
    """Parse HTTP request and extract headers and body"""

    try:
        # Split headers and body
        headers_raw, body = data.split(b'\r\n\r\n', 1)
        
        # Split headers into lines
        header_lines = headers_raw.split(b'\r\n')
        
        # Parse first line (request line)
        request_method, request_path, request_version = header_lines[0].split(b' ', 2)
        
        # Parse remaining headers
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
        print(f"Error parsing HTTP request: {e}")
        traceback.print_exc()
        return None, None
    
def format_error_response(status_line, error_msg):
    """Helper function to create properly formatted error responses"""

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


def receive_all(sock, expected_length=None):
    """Receive all data from the socket."""

    data = b""
    while True:
        chunk = sock.recv(ProtocolConfig.MAX_MSG_LENGTH)
        if not chunk:
            break
        data += chunk
        if expected_length and len(data) >= expected_length:
            break
    return data

def download_file(file_name, file):
    with open(file_name, "wb") as f:
        if isinstance(file, str):
            f.write(file.encode())  # המרה ל-bytes אם מקבלים string
        else:
            f.write(file)  # אם כבר bytes
    print(f"File saved to {file_name}")


def validate_certificate(cert_data: bytes) -> bool:
    """Validate certificate format."""

    return (cert_data.startswith(b'-----BEGIN CERTIFICATE-----') and 
            cert_data.endswith(b'-----END CERTIFICATE-----\n'))