import socket
import ssl
import protocol
import re
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.bindings.openssl.binding import Binding
import os
import time


def generate_private_key_and_csr(common_name):
    # יצירת מפתח פרטי RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Create a Client CSR
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Lev Academic Center"),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Kochav Yaakov"),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Jerusalem"),
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "IL"),
    ])

    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256(), default_backend())

    # המרת CSR לפורמט PEM
    csr_pem = csr.public_bytes(encoding=serialization.Encoding.PEM)

    # החזרת המפתח הפרטי ו-CSR בפורמט PEM
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    return private_key_pem, csr_pem


def create_client_ssl_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.set_ciphers('AES128-SHA256')
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def parse_http_response(response):
    """Parse HTTP response and extract headers and body"""
    headers = None
    body = None
    try:
        # Attempt to decode the response
        response_str = response.decode('utf-8', errors='replace')

        # Look for the header-body separator
        if '\r\n\r\n' in response_str:
            headers, body = response_str.split('\r\n\r\n', 1)
        elif '\n\n' in response_str:  # Fallback for \n\n only
            headers, body = response_str.split('\n\n', 1)
        else:
            raise ValueError("Header-body separator not found in response.")

    except Exception as e:
        print(f"Error parsing HTTP response: {e}")
        print(f"Raw response received:\n{response.decode('utf-8', errors='replace')}")

    return headers, body

def receive_certificate(secure_sock, timeout=30, debug=False):
    try:
        # Set socket timeout
        secure_sock.settimeout(timeout)

        full_response = b""
        total_received = 0
        body = b"" # Initialize body

        while True:
            try:
                chunk = secure_sock.recv(8192)

                if not chunk:
                    print("No more data received from server, connection closed.")
                    break
                
                full_response += chunk
                total_received += len(chunk)
                print(f"Received {len(chunk)} bytes. Total received: {total_received} bytes")

                # Check if we have enough data for headers
                if b'\r\n\r\n' in full_response or b'\n\n' in full_response:
                    headers, body = None, None
                    try:
                        response_str = full_response.decode('utf-8', errors='replace')
                        if '\r\n\r\n' in response_str:
                            headers, body = response_str.split('\r\n\r\n', 1)
                        elif '\n\n' in response_str:
                            headers, body = response_str.split('\n\n', 1)
                        else:
                            raise ValueError("Header-body separator not found in response.")
                    except Exception as e:
                        if debug:
                            print(f"Error parsing HTTP response: {e}")
                            print(f"Raw response received:\n{full_response.decode('utf-8', errors='replace')}")
                        return None
                    
                    # Headers are parsed, look for content-length
                    content_length = None
                    if headers:
                        try:
                            content_length = int(re.search(r'Content-Length:\s*(\d+)', headers).group(1))
                        except (AttributeError, ValueError): # Handle cases where the regex doesn't match or the value isn't an int
                           try:
                               content_length = int(headers.split("Content-Length:")[1].split("\n")[0].strip())
                           except (IndexError, ValueError):
                               print("Content-Length header not found or invalid.")
                               return None
                    else:
                        print("No headers received or parsed, exiting certificate receive.")
                        return None
                    
                    if len(body.encode('utf-8')) < content_length:
                        if debug:
                            print(f"Partial body received, content-length:{content_length}. Received:{len(body.encode('utf-8'))}. Still receiving chunks.")
                        continue #Continue reading until we have the complete body
                    elif len(body.encode('utf-8')) == content_length:
                        certificate = body.encode('utf-8')
                        
                        # Validate certificate format
                        if certificate.startswith(b'-----BEGIN CERTIFICATE-----') and \
                        certificate.endswith(b'-----END CERTIFICATE-----\n'):
                            print(f"Certificate received successfully. Length: {len(certificate)} bytes")
                            print(f"Certificate preview (first 200 bytes): {certificate[:200]}")

                            # Debugging output
                            print("\nFull Response Debugging:")
                            print("Total bytes received:", total_received)
                            print("Response (hex):", full_response.hex())
                            try:
                                print("Response (utf-8):", full_response.decode('utf-8', errors='replace'))
                            except Exception as decode_error:
                                print(f"Decode error: {decode_error}")

                            return certificate
                        else:
                           print("Received certificate data but its format is incorrect.")
                           return None
                    else:
                      print(f"Error body length:{len(body.encode('utf-8'))} is greater than content length:{content_length}")
                      return None # Error, received more data than content-length

            except ssl.SSLWantReadError:
                # SSL buffer not ready, continue
                time.sleep(0.1)
                continue
            except TimeoutError:
                print("Receive timeout")
                
                # If there is a partial HTTP response, still try to extract the certificate.
                if b'\r\n\r\n' in full_response or b'\n\n' in full_response:
                    headers, body = None, None
                    try:
                        response_str = full_response.decode('utf-8', errors='replace')
                        if '\r\n\r\n' in response_str:
                            headers, body = response_str.split('\r\n\r\n', 1)
                        elif '\n\n' in response_str:
                            headers, body = response_str.split('\n\n', 1)
                        else:
                            raise ValueError("Header-body separator not found in response.")
                    except Exception as e:
                        if debug:
                            print(f"Error parsing HTTP response: {e}")
                            print(f"Raw response received:\n{full_response.decode('utf-8', errors='replace')}")
                        return None
                    
                   # Headers are parsed, look for content-length
                    content_length = None
                    if headers:
                        try:
                            content_length = int(re.search(r'Content-Length:\s*(\d+)', headers).group(1))
                        except (AttributeError, ValueError): # Handle cases where the regex doesn't match or the value isn't an int
                           try:
                               content_length = int(headers.split("Content-Length:")[1].split("\n")[0].strip())
                           except (IndexError, ValueError):
                               print("Content-Length header not found or invalid.")
                               return None
                    else:
                       print("No headers received or parsed, exiting certificate receive.")
                       return None
                       
                    if len(body.encode('utf-8')) == content_length:
                        certificate = body.encode('utf-8')
                        
                        # Validate certificate format
                        if certificate.startswith(b'-----BEGIN CERTIFICATE-----') and \
                        certificate.endswith(b'-----END CERTIFICATE-----\n'):
                            print("Extracted certificate from partial response")
                            return certificate
                        else:
                           print("Received certificate data but its format is incorrect.")
                           return None
                    else:
                       print("Partial response with insufficient body, discarding data.")
                       return None # Do not attempt to parse if content length is incorrect.
                                   
                break
            except Exception as e:
                print(f"Error receiving certificate: {e}")
                if b'\r\n\r\n' in full_response or b'\n\n' in full_response:
                    headers, body = None, None
                    try:
                        response_str = full_response.decode('utf-8', errors='replace')
                        if '\r\n\r\n' in response_str:
                            headers, body = response_str.split('\r\n\r\n', 1)
                        elif '\n\n' in response_str:
                            headers, body = response_str.split('\n\n', 1)
                        else:
                            raise ValueError("Header-body separator not found in response.")
                    except Exception as e:
                        if debug:
                            print(f"Error parsing HTTP response: {e}")
                            print(f"Raw response received:\n{full_response.decode('utf-8', errors='replace')}")
                        return None
                    
                    # Headers are parsed, look for content-length
                    content_length = None
                    if headers:
                        try:
                            content_length = int(re.search(r'Content-Length:\s*(\d+)', headers).group(1))
                        except (AttributeError, ValueError): # Handle cases where the regex doesn't match or the value isn't an int
                            try:
                                content_length = int(headers.split("Content-Length:")[1].split("\n")[0].strip())
                            except (IndexError, ValueError):
                                print("Content-Length header not found or invalid.")
                                return None
                    else:
                       print("No headers received or parsed, exiting certificate receive.")
                       return None
                    
                    if len(body.encode('utf-8')) == content_length:
                        certificate = body.encode('utf-8')
                        
                        # Validate certificate format
                        if certificate.startswith(b'-----BEGIN CERTIFICATE-----') and \
                        certificate.endswith(b'-----END CERTIFICATE-----\n'):
                            print("Extracted certificate from partial response")
                            return certificate
                        else:
                           print("Received certificate data but its format is incorrect.")
                           return None
                    else:
                       print("Partial response with insufficient body, discarding data.")
                       return None # Do not attempt to parse if content length is incorrect
                
                break
    
    except Exception as overall_error:
        print(f"Overall certificate receive error: {overall_error}")
    
    return None

def client():
    context = create_client_ssl_context()
    print(f"Connecting to {protocol.SERVER_IP}:{protocol.SERVER_PORT}")

    try:
        with socket.create_connection((protocol.SERVER_IP, protocol.SERVER_PORT), timeout=protocol.TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=protocol.SERVER_HOSTNAME) as secure_sock:
                # Add more detailed connection logging
                print(f"Handshake successful with {secure_sock.getpeername()}")
                print(f"Using cipher: {secure_sock.cipher()}")
                print(f"SSL version: {secure_sock.version()}")

                # Set socket timeout explicitly
                secure_sock.settimeout(protocol.TIMEOUT)

                try:
                    # Generate CSR
                    private_key_pem, csr = generate_private_key_and_csr(protocol.CLIENT_HOSTNAME)
                    
                    # Create HTTP POST request
                    http_request = (
                        f"POST /sign_csr HTTP/1.1\r\n"
                        f"Host: {protocol.SERVER_HOSTNAME}\r\n"
                        f"Content-Length: {len(csr)}\r\n"
                        f"Content-Type: application/x-pem-file\r\n"
                        f"\r\n"
                    ).encode('utf-8') + csr
                    
                    # Send HTTP request with CSR
                    secure_sock.sendall(http_request)
                    print("CSR sent successfully")
                    
                    # Receive signed certificate using the dedicated function
                    certificate = receive_certificate(secure_sock, timeout=protocol.TIMEOUT, debug=True)
                    
                    if certificate:
                        # Save the private key and certificate
                        with open("client_private.key", "wb") as f:
                            f.write(private_key_pem)
                        with open("client_signed.crt", "wb") as f:
                            f.write(certificate)
                        print("Certificate and private key saved successfully")
                    else:
                        print("Failed to receive valid certificate")
                    
                except Exception as e:
                    print(f"Error in certificate exchange: {e}")
                    return

    except Exception as e:
        print(f"Connection error: {e}")
    finally:
        print("Connection closed")


if __name__ == "__main__":
    client()
