"""
Certificate Authority Server
Handles certificate signing requests and manages SSL connections.
"""
from typing import Optional, Tuple
import logging
import tempfile
import traceback
import os

import socket
import ssl

from ..protocol import CAConfig, SSLConfig
from ..utils.ca import (
    verify_client_csr,
    sign_csr_with_ca,
    download_file,
    monitor_content_length,
    read_http_request,
    read_request_body,
    send_error_response
)

def create_ca_server_ssl_context(cert: bytes, key: bytes) -> ssl.SSLContext:
    """Create an SSL context for the CA server."""
    cert_bytes = cert.encode() if isinstance(cert, str) else cert
    key_bytes = key.encode() if isinstance(key, str) else key

    # Create temporary files for cert and key
    # It's generally better to handle potential exceptions during file operations
    cert_path = None
    key_path = None
    try:
        # Create temporary files within a try block
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cert_file, \
             tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as key_file:
            cert_file.write(cert_bytes)
            key_file.write(key_bytes)
            cert_path = cert_file.name
            key_path = key_file.name

        # Use PROTOCOL_TLS_SERVER for better compatibility and security
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # Set cipher suites if defined in SSLConfig
        if hasattr(SSLConfig, 'CIPHER_SUITE') and SSLConfig.CIPHER_SUITE:
             context.set_ciphers(SSLConfig.CIPHER_SUITE)
        # These settings are generally NOT recommended for a real CA,
        # but might be specific to the CTF challenge.
        # context.check_hostname = False # Usually True for clients
        context.verify_mode = ssl.CERT_NONE # Usually ssl.CERT_REQUIRED for servers validating clients

        # Load the certificate chain using the paths obtained from temp files
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)

        return context

    except Exception as e:
        logging.error(f"Failed to create SSL context: {e}")
        # Ensure cleanup of temp files if context creation fails
        if cert_path and os.path.exists(cert_path):
            os.remove(cert_path)
        if key_path and os.path.exists(key_path):
            os.remove(key_path)
        raise # Re-raise the exception after cleanup attempt
    finally:
        # Clean up the temporary files after context is created and loaded
        # Note: If the context holds references, deleting might be problematic.
        # Consider registering cleanup with atexit or managing lifetime differently.
        # For simplicity here, we'll remove them, but be aware of potential issues.
        if cert_path and os.path.exists(cert_path):
             try:
                 os.remove(cert_path)
             except OSError as e:
                 logging.warning(f"Could not remove temp cert file {cert_path}: {e}")
        if key_path and os.path.exists(key_path):
             try:
                 os.remove(key_path)
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
        # Initialize server certificates
        download_file("ca.crt", CAConfig.CERT)
        self.cert_bytes = CAConfig.CERT.encode() if isinstance(CAConfig.CERT, str) else CAConfig.CERT
        self.key_bytes = CAConfig.KEY.encode() if isinstance(CAConfig.KEY, str) else CAConfig.KEY
        
        # Create SSL context
        self.context = create_ca_server_ssl_context(self.cert_bytes, self.key_bytes)

        # Setup server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((CAConfig.IP, CAConfig.PORT))
        self.server_socket.listen(5)
        logging.info(f"CA Server initialized on {CAConfig.IP}:{CAConfig.PORT}")

    def handle_client_request(self, ssl_socket: ssl.SSLSocket) -> bool:
        """Handle incoming CSR request"""
        try:
            # Receive and parse request
            headers, initial_body = read_http_request(ssl_socket)
            if not headers:
                send_error_response(ssl_socket, b"HTTP/1.1 400 Bad Request", b"Invalid HTTP request")
                return False

            # Validate and fix Content-Length
            try:
                # Case-insensitive lookup for Content-Length header
                content_length_header = next((v for k, v in headers.items() if k.lower() == b'content-length'), b'0')
                declared_length = int(content_length_header)
            except ValueError:
                send_error_response(ssl_socket, b"HTTP/1.1 400 Bad Request", b"Invalid Content-Length")
                return False

            # Read complete request body using the declared length
            body = read_request_body(ssl_socket, initial_body, declared_length)
            
            actual_length = len(body)
            # Check if sizes match
            if not monitor_content_length(actual_length, declared_length, "SERVER", "RECEIVED"):
                send_error_response(ssl_socket, b"HTTP/1.1 403 Forbidden", b"Content-Length mismatch")
                return False  # Continue to next client request, because we can't trust the data
            
            # Extract original CSR and embedded length
            original_csr, embedded_length = self._extract_original_csr_length(body)
            
            # Check for embedded length mismatch - additional security check
            if embedded_length is not None and actual_length != embedded_length:
                send_error_response(ssl_socket, b"HTTP/1.1 403 Forbidden", b"CSR tampering detected: embedded length mismatch")
                return False
                
            if not original_csr:
                send_error_response(ssl_socket, b"HTTP/1.1 400 Bad Request", b"No CSR provided")
                return False

            # Process CSR - verify and sign
            csr_obj = verify_client_csr(original_csr)
            if not csr_obj:
                send_error_response(ssl_socket, b"HTTP/1.1 403 Forbidden", b"Invalid CSR")
                return False

            # Sign certificate
            crt_file = sign_csr_with_ca(csr_pem=original_csr, ca_key_pem=self.key_bytes, ca_cert_pem=self.cert_bytes)
            if not crt_file:
                send_error_response(ssl_socket, b"HTTP/1.1 500 Internal Server Error", b"Certificate signing failed")
                return False

            # Send response
            self._send_signed_certificate(ssl_socket, crt_file)
            return True

        except Exception as e:
            logging.error(f"Error handling CSR request: {e}")
            #traceback.print_exc()
            send_error_response(ssl_socket, b"HTTP/1.1 500 Internal Server Error", b"Internal server error")
            return False
    
    def _send_signed_certificate(self, ssl_socket: ssl.SSLSocket, crt_file: bytes) -> None:
        """Send signed certificate back to client"""
        # Prepare response headers
        certificate_length = len(crt_file)
        # if certificate_length > 10000 #CAConfig.MAX_CERT_SIZE:
        #     send_error_response(ssl_socket, b"HTTP/1.1 413 Payload Too Large", b"Certificate size exceeds limit")
        #     return
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
        
        # verify that the response length matches the declared Content-Length
        if certificate_length != int(response_headers[2].split(b":")[1].strip()):
            send_error_response(ssl_socket, b"HTTP/1.1 500 Internal Server Error", b"Response Content-Length error")
            return
        ssl_socket.sendall(response)

        headers_length = len(b"\r\n".join(response_headers))
        logging.debug("=== Response Debug Info ===")
        logging.debug(f"Headers length: {headers_length} bytes")
        logging.debug(f"Certificate length: {len(crt_file)} bytes")
        logging.debug(f"Total response length: {len(response)} bytes")
        
        
        logging.info(f"Total response sent: {len(response)} bytes")
        logging.info("Certificate sent successfully")

    def _extract_original_csr_length(self, csr_data: bytes) -> Tuple[bytes, Optional[int]]:
        """Extract the CSR and its declared length from padded data."""
        padding_marker = b"PADDING_START_1234567890_CHECKSUM_"
        
        if padding_marker in csr_data:
            # Find position of padding marker
            marker_pos = csr_data.find(padding_marker)
            
            # Extract original CSR and length info
            original_csr = csr_data[:marker_pos]
            length_info = csr_data[marker_pos + len(padding_marker):]
            
            try:
                declared_length = int(length_info)
                return original_csr, declared_length
            except ValueError:
                return csr_data, None
        else:
            return csr_data, None
        
    def run(self) -> None:
        """Run the CA server"""
        if not self.server_socket:
            self.initialize()

        try:
            while True:  # Don't stop until successful get correct certificate
                client_socket, addr = self.server_socket.accept()
                logging.info(f"Client connected: {addr}")

                try:
                    with self.context.wrap_socket(client_socket, server_side=True) as ssl_socket:
                        if self.handle_client_request(ssl_socket):
                            logging.info("CA challenge completed successfully!")
                            break  # Exit after successful certificate signing
                except ssl.SSLError as e:
                    logging.error(f"SSL error: {e}")
        except KeyboardInterrupt:
            logging.info("\nShutting down CA server.")
        finally:
            if self.server_socket:
                self.server_socket.close()
            logging.info("CA server stopped.")

    def __del__(self):
        """Cleanup on destruction"""
        if self.server_socket:
            self.server_socket.close()
        logging.info("CA server socket closed")
        if self.context:
            self.context = None

if __name__ == "__main__":
    # Setup basic logging when run directly
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    ca_server = CAChallenge()
    try:
        ca_server.initialize() # Initialize before running
        ca_server.run()
    except Exception as e:
        logging.error(f"CA Server failed to start or run: {e}")
        #traceback.print_exc()