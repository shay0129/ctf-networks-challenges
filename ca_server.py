import socket
import ssl
import time
import protocol
import select
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os
import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import tempfile
from OpenSSL import crypto
import random
import traceback

def create_ca_cert():
    """
    Creates a self-signed Certificate Authority (CA) certificate and key.
    Returns the CA certificate and private key in PEM format as bytes.
    """
    # Define CA details
    class CA:
        def __init__(self, country, state, city, org_name, org_unit, domain_name):
            self.country = country
            self.state = state
            self.city = city
            self.org_name = org_name
            self.org_unit = org_unit
            self.domain_name = domain_name

    # Initialize CA with details
    ca = CA(
        country="IR",
        state="Tehran",
        city="Tehran",
        org_name="IRGC",
        org_unit="Cybersecurity",
        domain_name="IRGC Root CA"
    )

    # Generate RSA private key for the CA
    private_key = crypto.PKey()
    private_key.generate_key(crypto.TYPE_RSA, 4096)

    # Create a self-signed certificate
    certificate = crypto.X509()

    # Set certificate subject details
    subject = certificate.get_subject()
    subject.C = ca.country
    subject.ST = ca.state
    subject.L = ca.city
    subject.O = ca.org_name
    subject.OU = ca.org_unit
    subject.CN = ca.domain_name

    # Assign a random serial number to the certificate
    certificate.set_serial_number(random.getrandbits(64))

    # Set the certificate validity period (1 year)
    certificate.gmtime_adj_notBefore(0)
    certificate.gmtime_adj_notAfter(31536000)  # 1 year in seconds

    # Set the issuer as the subject (self-signed)
    certificate.set_issuer(subject)

    # Set the public key for the certificate
    certificate.set_pubkey(private_key)

    # Sign the certificate with the private key using SHA-512
    certificate.sign(private_key, 'sha512')

    # Convert certificate and private key to PEM format
    ca_certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, certificate)
    ca_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key)

    # Return the CA certificate and private key as PEM-formatted bytes
    return ca_certificate, ca_key

def receive_all(sock, expected_length=None):
    """Receive all data from the socket."""
    data = b""
    while True:
        chunk = sock.recv(protocol.MAX_MSG_LENGTH)
        if not chunk:
            break
        data += chunk
        if expected_length and len(data) >= expected_length:
            break
    return data

def verify_client_csr(csr_data):
    """Verify the client's Certificate Signing Request (CSR)."""
    try:
        csr_obj = x509.load_pem_x509_csr(csr_data, default_backend())

        # Verify signature on CSR
        csr_obj.public_key().verify(
            csr_obj.signature,
            csr_obj.tbs_certrequest_bytes,
            padding.PKCS1v15(),
            csr_obj.signature_hash_algorithm,
        )

        # Validate that the CN matches the expected value
        subject = csr_obj.subject
        for attribute in subject:
            if attribute.oid == x509.NameOID.COMMON_NAME:
                if attribute.value != "shay-ctf@example.com":
                    raise ValueError("CSR Common Name does not match expected value.")

        print("CSR verification successful.")
        return csr_obj
    except Exception as e:
        print(f"CSR verification failed: {e}")
        return None

def sign_ca(csr_obj, ca_cert_pem, ca_key_pem) -> bytes:
    if ca_cert_pem.startswith(b"-----BEGIN CERTIFICATE-----") and ca_key_pem.startswith(b"-----BEGIN PRIVATE KEY-----"):
        try:
            # Load the CA private key from the PEM data
            ca_key = load_pem_private_key(ca_key_pem, password=None, backend=default_backend())

            # Load the CA certificate to extract the issuer details
            ca_cert = x509.load_pem_x509_certificate(ca_cert_pem, default_backend())
            issuer = ca_cert.subject

            # Build the certificate
            cert = (
                x509.CertificateBuilder()
                .subject_name(csr_obj.subject)
                .issuer_name(issuer)
                .public_key(csr_obj.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.utcnow())
                .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None),
                    critical=True,
                )
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        key_encipherment=True,
                        content_commitment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        encipher_only=False,
                        decipher_only=False,
                        key_cert_sign=False,
                        crl_sign=False,
                    ),
                    critical=True,
                )
                .sign(ca_key, hashes.SHA256(), default_backend())
            )

            # Return the signed certificate in PEM format
            return cert.public_bytes(serialization.Encoding.PEM)
        except ValueError as e:
            print(f"Error loading key or certificate: {e}")
            return None
        except InvalidSignature as e:
            print(f"Error signing certificate: {e}")
            return None
        except Exception as e:
            print(f"Unexpected error signing certificate: {e}")
            return None
    else:
        print("Invalid PEM format for CA cert or key")
        return None

def create_server_ssl_context(cert,key) -> ssl.SSLContext:
    """Create and configure the server's SSL context."""
    # Create temporary files for the certificate and key
    with tempfile.NamedTemporaryFile(delete=False) as cert_file:
        cert_file.write(cert)
        cert_file_path = cert_file.name

    with tempfile.NamedTemporaryFile(delete=False) as key_file:
        key_file.write(key)
        key_file_path = key_file.name

    # Create an SSL context for the server
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.set_ciphers("AES128-SHA256")
    context.check_hostname = False

    # Load the certificate and key into the context
    context.load_cert_chain(certfile=cert_file_path, keyfile=key_file_path)

    return context

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
    
def receive_certificate(secure_sock, timeout=30, debug=False):
    try:
        # Set socket timeout
        secure_sock.settimeout(timeout)

        # קריאת ה-headers
        headers = b""
        while b"\r\n\r\n" not in headers:
            chunk = secure_sock.recv(4096)
            if not chunk:
                print("Connection closed while reading headers")
                return None
            headers += chunk

        # פיצול ל-headers ו-body התחלתי
        header_data, body = headers.split(b"\r\n\r\n", 1)
        
        # הדפסת headers לדיבוג
        print("=== Received Headers ===")
        print(header_data.decode('utf-8'))
        print("======================")

        # חיפוש Content-Length
        content_length = None
        for line in header_data.split(b"\r\n"):
            if b"Content-Length:" in line:
                content_length = int(line.split(b":", 1)[1].strip())
                print(f"Found Content-Length: {content_length}")
                break

        if content_length is None:
            print("Content-Length header missing")
            return None

        # קריאת שאר ה-body
        while len(body) < content_length:
            chunk = secure_sock.recv(4096)
            if not chunk:
                print(f"Connection closed before receiving full body. Got {len(body)} of {content_length} bytes")
                return None
            body += chunk
            if debug:
                print(f"Received chunk: {len(chunk)} bytes. Total: {len(body)}/{content_length}")

        if len(body) == content_length:
            if body.startswith(b"-----BEGIN CERTIFICATE-----") and body.endswith(b"-----END CERTIFICATE-----\n"):
                return body
            else:
                print("Invalid certificate format")
                print("Received data:", body[:100], "...")
        else:
            print(f"Body length mismatch. Expected {content_length}, got {len(body)}")
            
        return None

    except Exception as e:
        print(f"Error receiving certificate: {e}")
        return None
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

def handle_client_request(ssl_socket, ca_cert_pem, ca_key_pem) -> bool:
    try:
        # Receive the initial request data
        request_data = b""
        while b'\r\n\r\n' not in request_data:
            chunk = ssl_socket.recv(4096)
            if not chunk:
                return False
            request_data += chunk

        # Parse HTTP headers
        headers, initial_body = parse_http_request(request_data)
        if not headers:
            response = format_error_response(
                b"HTTP/1.1 400 Bad Request",
                b"Invalid HTTP request"
            )
            ssl_socket.sendall(response)
            return False

        # Verify request method and path
        if headers.get(b'request_method') != b'POST':
            response = format_error_response(
                b"HTTP/1.1 405 Method Not Allowed",
                b"Only POST method is allowed"
            )
            ssl_socket.sendall(response)
            return False

        # Get Content-Length
        try:
            content_length = int(headers.get(b'content-length', b'0'))
        except ValueError:
            response = format_error_response(
                b"HTTP/1.1 400 Bad Request",
                b"Invalid Content-Length"
            )
            ssl_socket.sendall(response)
            return False
        
        # Read remaining body data if necessary
        body = initial_body
        while len(body) < content_length:
            chunk = ssl_socket.recv(min(4096, content_length - len(body)))
            if not chunk:
                break
            body += chunk

        if not body:
            response = format_error_response(
                b"HTTP/1.1 400 Bad Request",
                b"No CSR provided"
            )
            ssl_socket.sendall(response)
            return False

        # Verify and process CSR
        csr_obj = verify_client_csr(body)
        if not csr_obj:
            response = format_error_response(
                b"HTTP/1.1 403 Forbidden",
                b"Invalid CSR"
            )
            ssl_socket.sendall(response)
            return False

        # Sign the CSR
        signed_cert = sign_ca(csr_obj, ca_cert_pem, ca_key_pem)
        if not signed_cert:
            response = format_error_response(
                b"HTTP/1.1 500 Internal Server Error",
                b"Certificate signing failed"
            )
            ssl_socket.sendall(response)
            return False

        # Prepare successful response
        content_length = str(len(signed_cert)).encode('utf-8')
        response_headers = [
            b"HTTP/1.1 200 OK",
            b"Content-Type: application/x-pem-file",
            b"Content-Length: " + content_length,
            b"Connection: close",
            b"",
            b""
        ]
        
        # Create full response
        response = b"\r\n".join(response_headers) + signed_cert
        
        # Debug logging
        print("=== Response Debug Info ===")
        headers_length = len(b"\r\n".join(response_headers))
        print(f"Headers length: {headers_length} bytes")
        print(f"Certificate length: {len(signed_cert)} bytes")
        print(f"Total response length: {len(response)} bytes")
        print("Headers:")
        try:
            print(b"\r\n".join(response_headers).decode('utf-8'))
        except UnicodeDecodeError:
            print("(Unable to decode headers)")
        print("=========================")
        
        # Send complete response
        try:
            ssl_socket.sendall(response)
            print(f"Total response sent: {len(response)} bytes")
            print("Certificate sent successfully")
            return True
            
        except Exception as send_error:
            print(f"Error sending response: {send_error}")
            traceback.print_exc()
            return False

    except Exception as e:
        print(f"Error handling client request: {e}")
        traceback.print_exc()
        response = format_error_response(
            b"HTTP/1.1 500 Internal Server Error",
            b"Internal server error"
        )
        try:
            ssl_socket.sendall(response)
        except:
            pass
        return False

def main():
    ca_cert_pem, ca_key_pem = create_ca_cert()
    context = create_server_ssl_context(ca_cert_pem, ca_key_pem)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((protocol.SERVER_IP, protocol.SERVER_PORT))
        server_socket.listen(5)

        print(f"Server listening on {protocol.SERVER_IP}:{protocol.SERVER_PORT}")

        try:
            while True:
                client_socket, addr = server_socket.accept()
                print(f"Client connected: {addr}")

                try:
                    with context.wrap_socket(client_socket, server_side=True) as ssl_socket:
                        handle_client_request(ssl_socket, ca_cert_pem, ca_key_pem)
                except ssl.SSLError as e:
                    print(f"SSL error: {e}")
        except KeyboardInterrupt:
            print("\nShutting down the server.")
        finally:
            print("Server stopped.")

if __name__ == "__main__":
    main()