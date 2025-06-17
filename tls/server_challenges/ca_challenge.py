# type: ignore[attr-defined], ignore[reportPrivateUsage], ignore[reportPrivateUsage]
"""
Certificate Authority Server
Handles certificate signing requests and manages SSL connections.
"""
import logging
import tempfile
import os

import socket
import ssl
import warnings

# --- Suppress the specific RuntimeWarning ---
warnings.filterwarnings(
    action='ignore',
    # Pass the regex pattern as a raw string, not a compiled object
    message=r".*'tls\.server_challenges\.ca_challenge'.*found in sys\.modules.*",
    category=RuntimeWarning
    # Note: re.IGNORECASE is not directly used here, but the pattern is likely sufficient.
)
# --- End warning suppression ---

from ..protocol import CAConfig, SSLConfig
from ..utils.ca import (
    verify_client_csr,
    sign_csr_with_ca,
    download_file,
    read_http_request,
    send_error_response,
    extract_csr,
    validate_csr_checksum
)

# Constants
HTTP_OK = b"HTTP/1.1 200 OK"
HTTP_BAD_REQUEST = b"HTTP/1.1 400 Bad Request"
HTTP_FORBIDDEN = b"HTTP/1.1 403 Forbidden"
HTTP_SERVER_ERROR = b"HTTP/1.1 500 Internal Server Error"

# Configure logging minimally for CTF context
# Only show INFO and above by default, can be changed if needed for debugging
logging.basicConfig(
    level=logging.INFO, # Or logging.WARNING for even less output
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def create_ca_server_ssl_context(cert: bytes, key: bytes) -> ssl.SSLContext:
    """Create an SSL context for the CA server."""
    cert_bytes = cert.encode() if isinstance(cert, str) else cert
    key_bytes = key.encode() if isinstance(key, str) else key

    cert_path = None
    key_path = None
    try:
        # Use temporary files for cert and key
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cert_file, \
             tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as key_file:
            cert_file.write(cert_bytes)
            key_file.write(key_bytes)
            cert_path = cert_file.name
            key_path = key_file.name

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if hasattr(SSLConfig, 'CIPHER_SUITE') and SSLConfig.CIPHER_SUITE:
             context.set_ciphers(SSLConfig.CIPHER_SUITE)
        context.verify_mode = ssl.CERT_NONE # Specific to challenge

        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        # logging.debug("SSL context created successfully.") # Changed to DEBUG
        return context

    except Exception as e:
        logging.critical(f"Failed to create SSL context: {e}") # Keep critical errors
        # Ensure cleanup of temp files if context creation fails
        if cert_path and os.path.exists(cert_path):
            try: os.remove(cert_path)
            except OSError: pass
        if key_path and os.path.exists(key_path):
            try: os.remove(key_path)
            except OSError: pass
        raise
    finally:
        # Clean up the temporary files
        if cert_path and os.path.exists(cert_path):
             try: os.remove(cert_path)
             except OSError as e:
                 logging.warning(f"Could not remove temp cert file {cert_path}: {e}")
        if key_path and os.path.exists(key_path):
             try: os.remove(key_path)
             except OSError as e:
                 logging.warning(f"Could not remove temp key file {key_path}: {e}")

class CAChallenge:
    """Certificate Authority Server Challenge"""
    def __init__(self):
        self.cert_bytes = None
        self.key_bytes = None
        self.context = None
        self.server_socket = None

    def initialize(self) -> None:
        """Initialize CA server certificates and context"""
        try:
            # Initialize server certificates
            download_file("ca.crt", CAConfig.CERT) # For connect CTFServer
            self.cert_bytes = CAConfig.CERT.encode()
            self.key_bytes = CAConfig.KEY.encode()
            self.context = create_ca_server_ssl_context(self.cert_bytes, self.key_bytes)
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((CAConfig.IP, CAConfig.PORT))
            self.server_socket.listen(5)
            logging.info(f"CA Server listening on {CAConfig.IP}:{CAConfig.PORT}")
        except Exception as e:
            logging.critical(f"CA Server initialization failed: {e}")
            raise

    def handle_client_request(self, ssl_socket: ssl.SSLSocket) -> bool:
        """Handle incoming CSR request with enhanced logging"""
        try:
            #logging.info("🔍 [CA_SERVER] New CSR request received")
            headers, initial_body = self._read_and_validate_request(ssl_socket)
            if not headers or initial_body is None:
                return False
                
            #logging.info("📄 [CA_SERVER] Reading CSR from client request...")
            success, result = extract_csr(ssl_socket, headers, initial_body)
            if not success or not result:
                logging.warning("❌ [CA_SERVER] Failed to extract CSR from request")
                return False
                
            original_csr, padded_checksum = result
            #logging.info(f"📋 [CA_SERVER] CSR extracted successfully (length: {len(original_csr)} bytes)")
            
            # Log CSR details for CTF participants to see
            # try:
            #     from OpenSSL import crypto
            #     csr_obj = crypto.load_certificate_request(crypto.FILETYPE_PEM, original_csr)
            #     subject = csr_obj.get_subject()
            #     logging.info("🔍 [CA_SERVER] CSR Subject Details:")
            #     for component in subject.get_components():
            #         name = component[0].decode('utf-8')
            #         value = component[1].decode('utf-8')
            #         logging.info(f"    {name}: {value}")
            # except Exception as e:
            #     logging.warning(f"⚠️  [CA_SERVER] Could not parse CSR subject: {e}")
            
            if not validate_csr_checksum(original_csr, padded_checksum):
                #logging.warning("❌ [CA_SERVER] CSR checksum validation failed")
                return False
                
            verify_result = verify_client_csr(original_csr, ssl_socket)
            if not verify_result:
                #logging.warning("❌ [CA_SERVER] CSR verification failed")
                return False
                
            #logging.info("✅ [CA_SERVER] CSR verified successfully, signing certificate...")
            cert = self.sign_csr(original_csr)
            if not cert:
                #logging.error("❌ [CA_SERVER] Certificate signing failed")
                return False
                
            #logging.info("📜 [CA_SERVER] Certificate signed successfully, sending to client")
            self.send_cert(ssl_socket, cert)
            #logging.info("✅ [CA_SERVER] Certificate sent to client successfully")
            return True
        except Exception as e:
            #logging.critical(f"CA server error: {str(e)}")
            return False

    def _read_and_validate_request(self, ssl_socket: ssl.SSLSocket) -> tuple[dict[bytes, bytes] | None, bytes | None]:
        try:
            headers, initial_body = read_http_request(ssl_socket)
            if not headers:
                send_error_response(ssl_socket, b"HTTP/1.1 400 Bad Request", b"Invalid HTTP request")
                return None, None
            return headers, initial_body
        except Exception as e:
            logging.critical(f"Error reading HTTP request: {str(e)}")
            send_error_response(ssl_socket, b"HTTP/1.1 400 Bad Request", b"Error reading request")
            return None, None

    def sign_csr(self, csr: bytes) -> bytes | None:
        """Sign a CSR and return the certificate bytes, or None on error."""
        try:
            if self.key_bytes is None or self.cert_bytes is None:
                logging.critical("CA key or cert bytes are None")
                return None
                
            #logging.info("🔑 [CA_SERVER] Signing CSR with CA private key...")
            cert_bytes = sign_csr_with_ca(csr_pem=csr, ca_key_pem=self.key_bytes, ca_cert_pem=self.cert_bytes)
            
            if cert_bytes:
                # Log certificate details for verification
                try:
                    from OpenSSL import crypto
                    cert_obj = crypto.load_certificate(crypto.FILETYPE_PEM, cert_bytes)
                    subject = cert_obj.get_subject()
                    #logging.info("📜 [CA_SERVER] Signed Certificate Details:")
                    for component in subject.get_components():
                        name = component[0].decode('utf-8')
                        value = component[1].decode('utf-8')
                        #logging.info(f"    {name}: {value}")
                    #logging.info(f"📅 [CA_SERVER] Certificate valid from {cert_obj.get_notBefore().decode()} to {cert_obj.get_notAfter().decode()}")
                except Exception as e:
                    logging.warning(f"⚠️  [CA_SERVER] Could not parse signed certificate: {e}")
                    
            return cert_bytes
        except Exception as e:
            logging.critical(f"CA sign error: {str(e)}")
            return None

    def send_cert(self, ssl_socket: ssl.SSLSocket, cert: bytes) -> None:
        """Send the signed certificate to the client as a valid HTTP response."""
        try:
            #logging.info(f"📤 [CA_SERVER] Sending signed certificate to client ({len(cert)} bytes)")
            # Prepare HTTP response headers
            response_headers = b"HTTP/1.1 200 OK\r\n"
            response_headers += b"Content-Type: application/x-pem-file\r\n"
            response_headers += f"Content-Length: {len(cert)}\r\n".encode()
            response_headers += b"Connection: close\r\n\r\n"
            ssl_socket.sendall(response_headers + cert)
            #logging.info("✅ [CA_SERVER] Certificate response sent successfully")
        except Exception as e:
            logging.critical(f"CA send cert error: {e}")

    def run(self) -> None:
        if not self.server_socket:
            try:
                self.initialize()
            except Exception:
                return
        try:
            while True:
                try:
                    if not self.server_socket:
                        break
                    client_socket, _ = self.server_socket.accept()
                except OSError:
                    break
                try:
                    if not self.context:
                        continue
                    with self.context.wrap_socket(client_socket, server_side=True) as ssl_socket:
                        if self.handle_client_request(ssl_socket):
                            pass
                except ssl.SSLError as e:
                    if "UNKNOWN_PROTOCOL" not in str(e) and "WRONG_VERSION_NUMBER" not in str(e):
                        logging.warning(f"SSL error: {e}")
                except Exception as e:
                    logging.critical(f"Error during client handling: {e}")
                finally:
                    if client_socket.fileno() != -1:
                        try:
                            client_socket.close()
                        except Exception:
                            pass
        except KeyboardInterrupt:
            pass
        finally:
            if self.server_socket:
                try:
                    self.server_socket.close()
                except Exception:
                    pass

    def __del__(self):
        if self.server_socket and self.server_socket.fileno() != -1:
            try:
                self.server_socket.close()
            except Exception:
                pass
        self.context = None

if __name__ == "__main__":
    ca_server = CAChallenge()
    try:
        ca_server.run()
    except Exception as e:
        pass
    finally:
        pass
