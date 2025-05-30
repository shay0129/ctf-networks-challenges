# type: ignore[attr-defined]
"""
Certificate Authority Server
Handles certificate signing requests and manages SSL connections.
"""
import logging
import tempfile
# import traceback # No longer needed if we remove print_exc
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
    _extract_csr,  # type: ignore[reportPrivateUsage]
    _validate_csr_checksum  # type: ignore[reportPrivateUsage]
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
        logging.error(f"Failed to create SSL context: {e}") # Keep critical errors
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
            download_file("ca.crt", CAConfig.CERT)
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
        """Handle incoming CSR request"""
        try:
            headers: dict[bytes, bytes] | None
            initial_body: bytes | None
            headers, initial_body = self._read_and_validate_request(ssl_socket)
            if not headers or initial_body is None:
                return False
            # Use internal utility functions for CSR extraction and validation
            success, result = _extract_csr(ssl_socket, headers, initial_body)
            if not success or not result:
                return False
            original_csr, padded_checksum = result
            if not _validate_csr_checksum(original_csr, padded_checksum):
                send_error_response(ssl_socket, HTTP_FORBIDDEN, b"CSR checksum validation failed")
                return False
            verify_result = verify_client_csr(original_csr, ssl_socket)
            if not verify_result:
                send_error_response(ssl_socket, HTTP_FORBIDDEN, b"CSR verification failed")
                return False
            return self._sign_and_send_certificate(ssl_socket, original_csr)
        except ConnectionAbortedError:
            logging.warning("Client connection aborted.")
            return False
        except Exception as e:
            logging.error(f"Error handling client request: {str(e)}")
            if ssl_socket.fileno() != -1:
                try:
                    send_error_response(ssl_socket, HTTP_SERVER_ERROR, b"Internal server error")
                except Exception:
                    pass
            return False

    def _read_and_validate_request(self, ssl_socket: ssl.SSLSocket) -> tuple[dict[bytes, bytes] | None, bytes | None]:
        try:
            headers, initial_body = read_http_request(ssl_socket)
            if not headers:
                send_error_response(ssl_socket, b"HTTP/1.1 400 Bad Request", b"Invalid HTTP request")
                return None, None
            return headers, initial_body
        except Exception as e:
            logging.error(f"Error reading HTTP request: {str(e)}")
            send_error_response(ssl_socket, b"HTTP/1.1 400 Bad Request", b"Error reading request")
            return None, None

    def _sign_and_send_certificate(self, ssl_socket: ssl.SSLSocket, csr: bytes) -> bool:
        try:
            if self.key_bytes is None or self.cert_bytes is None:
                logging.error("CA key or cert bytes are None")
                send_error_response(ssl_socket, b"HTTP/1.1 500 Internal Server Error", b"CA key/cert missing")
                return False
            crt_file = sign_csr_with_ca(csr_pem=csr, ca_key_pem=self.key_bytes, ca_cert_pem=self.cert_bytes)
            if not crt_file:
                logging.error("Certificate signing failed")
                send_error_response(ssl_socket, b"HTTP/1.1 500 Internal Server Error", b"Certificate signing failed")
                return False
            self._send_signed_certificate(ssl_socket, crt_file)
            logging.info("Certificate signed and sent successfully.")
            return True
        except Exception as e:
            logging.error(f"Error signing/sending certificate: {str(e)}")
            send_error_response(ssl_socket, b"HTTP/1.1 500 Internal Server Error", b"Error generating certificate")
            return False

    def _send_signed_certificate(self, ssl_socket: ssl.SSLSocket, crt_file: bytes) -> None:
        """Send signed certificate back to client"""
        certificate_length = len(crt_file)
        if certificate_length > CAConfig.MAX_CERT_SIZE:
            send_error_response(ssl_socket, b"HTTP/1.1 413 Payload Too Large", b"Certificate size exceeds limit")
            return
        content_length = str(certificate_length).encode('utf-8')
        response_headers = [
            b"HTTP/1.1 200 OK",
            b"Content-Type: application/x-pem-file",
            b"Content-Length: " + content_length,
            b"Connection: close",
            b"",
            b""
        ]
        response = b"\r\n".join(response_headers) + crt_file

        # Internal check, no need to log error here, send_error_response handles it
        if certificate_length != int(response_headers[2].split(b":")[1].strip()):
            send_error_response(ssl_socket, b"HTTP/1.1 500 Internal Server Error", b"Response Content-Length error")
            return

        ssl_socket.sendall(response)
        #logging.debug("Certificate response sent.")

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
                    logging.info("Server socket closed, stopping.")
                    break
                try:
                    if not self.context:
                        continue
                    with self.context.wrap_socket(client_socket, server_side=True) as ssl_socket:
                        if self.handle_client_request(ssl_socket):
                            logging.info("Challenge interaction completed.")
                except ssl.SSLError as e:
                    if "UNKNOWN_PROTOCOL" not in str(e) and "WRONG_VERSION_NUMBER" not in str(e):
                        logging.warning(f"SSL error: {e}")
                except Exception as e:
                    logging.error(f"Error during client handling: {e}")
                finally:
                    if client_socket.fileno() != -1:
                        try:
                            client_socket.close()
                        except Exception:
                            pass
        except KeyboardInterrupt:
            logging.info("Shutdown signal received.")
        finally:
            if self.server_socket:
                try:
                    self.server_socket.close()
                    logging.info("CA server socket closed.")
                except Exception:
                    pass

    def __del__(self):
        """Cleanup on destruction"""
        # This might not be reliably called. Use 'finally' in run() for cleanup.
        if self.server_socket and self.server_socket.fileno() != -1:
            try:
                self.server_socket.close()
                # logging.debug("Socket closed in __del__") # DEBUG
            except Exception:
                pass
        self.context = None

if __name__ == "__main__":
    # Logging is configured at the top
    ca_server = CAChallenge()
    try:
        # initialize() is called within run() if needed
        ca_server.run()
    except Exception as e:
        # Critical failure already logged in initialize() or run()
        # logging.critical(f"CA Server failed unexpectedly: {e}") # Redundant?
        pass # Exit gracefully
    finally:
        logging.info("CA server process finished.")