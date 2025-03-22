"""
Certificate Authority Server
Handles certificate signing requests and manages SSL connections.
"""
import traceback
import socket
import ssl
import logging

from tls.protocol import CAConfig
from tls.utils.ca import (
    verify_client_csr,
    sign_csr_with_ca,
    download_file,
    monitor_content_length,
    read_http_request,
    read_request_body,
    send_error_response
)
from tls.protocol import SSLConfig
import tempfile

def create_ca_server_ssl_context(cert: bytes, key: bytes) -> ssl.SSLContext:
    """Create an SSL context for the CA server."""
    cert_bytes = cert.encode() if isinstance(cert, str) else cert
    key_bytes = key.encode() if isinstance(key, str) else key

    with tempfile.NamedTemporaryFile(delete=False) as cert_file, \
         tempfile.NamedTemporaryFile(delete=False) as key_file:
        cert_file.write(cert_bytes)
        key_file.write(key_bytes)
        cert_path, key_path = cert_file.name, key_file.name

    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.set_ciphers(SSLConfig.CIPHER_SUITE)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)

    return context

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

            # Validate Content-Length
            try:
                content_length = int(headers.get(b'content-length', b'0')) # 0 if not found
            except ValueError:
                send_error_response(ssl_socket, b"HTTP/1.1 400 Bad Request", b"Invalid Content-Length")
                return False

            # Read complete request body
            body = read_request_body(ssl_socket, initial_body, content_length)
            monitor_content_length(len(body), content_length, "SERVER", "RECEIVED")

            if not body:
                send_error_response(ssl_socket, b"HTTP/1.1 400 Bad Request", b"No CSR provided")
                return False

            # Process CSR
            csr_obj = verify_client_csr(body)
            if not csr_obj:
                send_error_response(ssl_socket, b"HTTP/1.1 403 Forbidden", b"Invalid CSR")
                return False

            # Sign certificate
            crt_file = sign_csr_with_ca(csr_pem=body, ca_key_pem=self.key_bytes, ca_cert_pem=self.cert_bytes)
            if not crt_file:
                send_error_response(ssl_socket, b"HTTP/1.1 500 Internal Server Error", b"Certificate signing failed")
                return False

            # Send response
            self._send_signed_certificate(ssl_socket, crt_file)
            return True

        except Exception as e:
            logging.error(f"Error handling CSR request: {e}")
            traceback.print_exc()
            send_error_response(ssl_socket, b"HTTP/1.1 500 Internal Server Error", b"Internal server error")
            return False

    def _send_signed_certificate(self, ssl_socket: ssl.SSLSocket, crt_file: bytes) -> None:
        """Send signed certificate back to client"""
        content_length = str(len(crt_file)).encode('utf-8')
        response_headers = [
            b"HTTP/1.1 200 OK",
            b"Content-Type: application/x-pem-file",
            b"Content-Length: " + content_length,
            b"Connection: close",
            b"",
            b""
        ]
        
        response = b"\r\n".join(response_headers) + crt_file
        
        headers_length = len(b"\r\n".join(response_headers))
        logging.debug("=== Response Debug Info ===")
        logging.debug(f"Headers length: {headers_length} bytes")
        logging.debug(f"Certificate length: {len(crt_file)} bytes")
        logging.debug(f"Total response length: {len(response)} bytes")
        
        ssl_socket.sendall(response)
        logging.info(f"Total response sent: {len(response)} bytes")
        logging.info("Certificate sent successfully")

    def run(self) -> None:
        """Run the CA server"""
        if not self.server_socket:
            self.initialize()

        try:
            while True:
                client_socket, addr = self.server_socket.accept()
                logging.info(f"Client connected: {addr}")

                try:
                    with self.context.wrap_socket(client_socket, server_side=True) as ssl_socket:
                        self.handle_client_request(ssl_socket)
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