"""
Certificate Authority Server
Handles certificate signing requests and manages SSL connections.
"""
from typing import Optional, Tuple
import logging
import tempfile
# import traceback # No longer needed if we remove print_exc
import os

import socket
import ssl
import warnings
import re

# --- Suppress the specific RuntimeWarning ---
warnings.filterwarnings(
    action='ignore',
    # Pass the regex pattern as a raw string, not a compiled object
    message=r".*'communication\.tls\.server_challenges\.ca_challenge'.*found in sys\.modules.*",
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
    read_request_body,
    send_error_response,
    _extract_csr,
    _validate_csr_checksum
)
from cryptography import x509 # Import x509 for type hinting if needed
from cryptography.x509.oid import NameOID # Import NameOID

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
            except OSError: pass # Ignore cleanup errors
        if key_path and os.path.exists(key_path):
            try: os.remove(key_path)
            except OSError: pass # Ignore cleanup errors
        raise
    finally:
        # Clean up the temporary files
        if cert_path and os.path.exists(cert_path):
             try: os.remove(cert_path)
             except OSError as e:
                 logging.warning(f"Could not remove temp cert file {cert_path}: {e}") # Keep cleanup warnings
        if key_path and os.path.exists(key_path):
             try: os.remove(key_path)
             except OSError as e:
                 logging.warning(f"Could not remove temp key file {key_path}: {e}") # Keep cleanup warnings

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
            download_file("ca.crt", CAConfig.CERT) # Assume download_file logs minimally
            self.cert_bytes = CAConfig.CERT.encode() if isinstance(CAConfig.CERT, str) else CAConfig.CERT
            self.key_bytes = CAConfig.KEY.encode() if isinstance(CAConfig.KEY, str) else CAConfig.KEY

            # Create SSL context
            self.context = create_ca_server_ssl_context(self.cert_bytes, self.key_bytes)

            # Setup server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((CAConfig.IP, CAConfig.PORT))
            self.server_socket.listen(5)
            logging.info(f"CA Server listening on {CAConfig.IP}:{CAConfig.PORT}") # Keep essential info
        except Exception as e:
            logging.critical(f"CA Server initialization failed: {e}") # Log critical failure
            raise # Re-raise to prevent server from running in a bad state

    def handle_client_request(self, ssl_socket: ssl.SSLSocket) -> bool:
        """Handle incoming CSR request"""
        try:
            # 1. Read and validate the HTTP request
            headers, initial_body = self._read_and_validate_request(ssl_socket)
            if not headers:
                return False
                
            # 2. Extract the CSR from the request body - שימוש בפונקציה מיובאת
            success, result = _extract_csr(ssl_socket, headers, initial_body)  # הסרת ה-self.
            if not success or not result:
                return False
                
            original_csr, padded_checksum = result
            
            # 3. Validate the CSR with the embedded checksum - שימוש בפונקציה מיובאת
            if not _validate_csr_checksum(original_csr, padded_checksum):  # הסרת ה-self.
                send_error_response(ssl_socket, HTTP_FORBIDDEN, b"CSR checksum validation failed")
                return False
            
            # 4. Verify CSR and get client name using the utility function
            result = verify_client_csr(original_csr, ssl_socket)
            if not result:
                send_error_response(ssl_socket, HTTP_FORBIDDEN, b"CSR verification failed")
                return False
                
            csr_obj, provided_name = result
            
            # 5. Sign the CSR and send the certificate back to the client
            return self._sign_and_send_certificate(ssl_socket, original_csr)
                
        except ConnectionAbortedError:
            logging.warning("Client connection aborted.")
            return False
        except Exception as e:
            logging.error(f"Error handling client request: {str(e)}")
            # Avoid sending 500 if connection is already broken
            if ssl_socket.fileno() != -1:
                try:
                    send_error_response(ssl_socket, HTTP_SERVER_ERROR, b"Internal server error")
                except Exception:
                    pass  # Ignore errors trying to send error on broken socket
            return False
    
    def _read_and_validate_request(self, ssl_socket: ssl.SSLSocket) -> Tuple[Optional[dict], Optional[bytes]]:
        """Read and validate HTTP request"""
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
    
    
            
    def _get_and_validate_client_name(self, ssl_socket: ssl.SSLSocket) -> Tuple[bool, Optional[str]]:
        """Get and validate client name from socket interaction"""
        try:
            # במקום לשלוח מחרוזת גולמית, נשלח תשובת HTTP מובנית
            name_prompt_message = b"Please enter your name: "
            response_headers = [
                HTTP_OK,  # שימוש בקבוע שהוגדר
                b"Content-Type: text/plain",
                b"Content-Length: " + str(len(name_prompt_message)).encode('utf-8'),
                b"Connection: keep-alive",  # חשוב לשמור את החיבור פתוח
                b"",
                b""
            ]
            
            # שליחת הודעה מובנית בפורמט HTTP
            http_response = b"\r\n".join(response_headers) + name_prompt_message
            ssl_socket.sendall(http_response)
            logging.debug("Sent name prompt via HTTP response")
            
            # קריאת התשובה - ניתן להשתמש ב-read_http_request כדי לקרוא בקשת HTTP מלאה
            headers, initial_body = read_http_request(ssl_socket)
            if not headers:
                logging.warning("Failed to receive valid HTTP request with name")
                send_error_response(ssl_socket, HTTP_BAD_REQUEST, b"Invalid name response format")
                return False, None
                
            # חילוץ השם מהבקשה - יכול להיות בגוף הבקשה או בפרמטר URL
            provided_name = initial_body.decode('utf-8').strip() if initial_body else ""
            
            # אם אין שם בגוף הבקשה, ננסה לחפש אותו בכותרות
            if not provided_name and headers.get(b'name'):
                provided_name = headers[b'name'].decode('utf-8').strip()
                
            # בדיקה שהשם אינו ריק
            if not provided_name:
                logging.warning("Empty name provided")
                send_error_response(ssl_socket, HTTP_BAD_REQUEST, b"Name cannot be empty")
                return False, None
                
            try:
                # אימות שהשם הוא שם X509 תקין
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, provided_name)])
                logging.info(f"Received valid name: {provided_name}")
                return True, provided_name
            except ValueError as ve:
                logging.warning(f"Invalid name format: {ve}")
                send_error_response(ssl_socket, HTTP_BAD_REQUEST, b"Invalid name format")
                return False, None
                
        except ConnectionAbortedError:
            logging.warning("Connection aborted while waiting for client name")
            return False, None
        except Exception as e:
            logging.error(f"Error getting client name: {str(e)}")
            send_error_response(ssl_socket, HTTP_SERVER_ERROR, b"Error processing client name")
            return False, None
            
    def _sign_and_send_certificate(self, ssl_socket: ssl.SSLSocket, csr: bytes) -> bool:
        """Sign CSR and send certificate to client"""
        try:
            # Sign certificate
            crt_file = sign_csr_with_ca(csr_pem=csr, ca_key_pem=self.key_bytes, ca_cert_pem=self.cert_bytes)
            if not crt_file:
                logging.error("Certificate signing failed")
                send_error_response(ssl_socket, b"HTTP/1.1 500 Internal Server Error", b"Certificate signing failed")
                return False
                
            # Send response
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
        """Run the CA server"""
        if not self.server_socket:
            try:
                self.initialize()
            except Exception:
                 # Initialization failed, already logged, exit.
                 return

        try:
            while True:
                try:
                    client_socket, addr = self.server_socket.accept()
                except OSError:
                    logging.info("Server socket closed, stopping.")
                    break # Exit loop if socket is closed

                try:
                    with self.context.wrap_socket(client_socket, server_side=True) as ssl_socket:
                        # logging.debug(f"SSL handshake successful with {addr}") # DEBUG
                        if self.handle_client_request(ssl_socket):
                            logging.info("Challenge interaction completed.") # Generic success
                            # Decide if you want the server to stop after one success
                            # break # Uncomment to stop after first success
                except ssl.SSLError as e:
                    # Log SSL errors minimally, they can be noisy
                    if "UNKNOWN_PROTOCOL" not in str(e) and "WRONG_VERSION_NUMBER" not in str(e):
                         logging.warning(f"SSL error: {e}")
                except Exception as e:
                     # Catch errors during wrap_socket or handle_client_request if not caught inside
                     logging.error(f"Error during client handling: {e}")
                finally:
                    # Ensure client socket is closed if not handled by 'with' statement (e.g., before wrap_socket)
                    if client_socket.fileno() != -1:
                        try: client_socket.close()
                        except Exception: pass

        except KeyboardInterrupt:
            logging.info("Shutdown signal received.")
        finally:
            if self.server_socket:
                try:
                    self.server_socket.close()
                    logging.info("CA server socket closed.")
                except Exception:
                    pass # Ignore errors during final close

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