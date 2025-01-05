"""
Certificate Authority Server
Handles certificate signing requests and manages SSL connections.
"""
import traceback
import socket
import ssl
import logging
from typing import Optional

from protocol import CAConfig
from ca_server_utils import (
    create_ca_server_ssl_context,
    verify_client_csr,
    sign_csr_with_ca,
    format_error_response,
    parse_http_request,
    download_file,
    monitor_content_length
)

def handle_client_request(ssl_socket: ssl.SSLSocket, ca_cert_pem: bytes, ca_key_pem: bytes) -> bool:
    """
    Handle incoming client CSR request.

    Args:
        ssl_socket: Established SSL connection
        ca_cert_pem: CA certificate in PEM format
        ca_key_pem: CA private key in PEM format

    Returns:
        True if request handled successfully, False otherwise
    """
    try:
        # Receive and parse request
        request_data = b""
        while b'\r\n\r\n' not in request_data:
            chunk = ssl_socket.recv(4096)
            if not chunk:
                return False
            request_data += chunk

        headers, initial_body = parse_http_request(request_data)
        if not headers:
            response = format_error_response(
                b"HTTP/1.1 400 Bad Request",
                b"Invalid HTTP request"
            )
            ssl_socket.sendall(response)
            return False

        # Validate Content-Length
        try:
            content_length = int(headers.get(b'content-length', b'0'))
        except ValueError:
            response = format_error_response(
                b"HTTP/1.1 400 Bad Request",
                b"Invalid Content-Length"
            )
            ssl_socket.sendall(response)
            return False
        
        # Read complete request body
        body = initial_body
        while len(body) < content_length:
            chunk = ssl_socket.recv(min(4096, content_length - len(body)))
            if not chunk:
                break
            body += chunk

        monitor_content_length(len(body), content_length, "SERVER", "RECEIVED")

        if not body:
            response = format_error_response(
                b"HTTP/1.1 400 Bad Request",
                b"No CSR provided"
            )
            ssl_socket.sendall(response)
            return False

        # Process CSR
        csr_obj = verify_client_csr(body)
        if not csr_obj:
            response = format_error_response(
                b"HTTP/1.1 403 Forbidden",
                b"Invalid CSR"
            )
            ssl_socket.sendall(response)
            return False

        # Sign certificate
        crt_file = sign_csr_with_ca(
            csr_pem=body, 
            ca_key_pem=ca_key_pem, 
            ca_cert_pem=ca_cert_pem
        )
        if not crt_file:
            response = format_error_response(
                b"HTTP/1.1 500 Internal Server Error",
                b"Certificate signing failed"
            )
            ssl_socket.sendall(response)
            return False

        # Send response
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
        
        # Log response details
        headers_length = len(b"\r\n".join(response_headers))
        logging.debug("=== Response Debug Info ===")
        logging.debug(f"Headers length: {headers_length} bytes")
        logging.debug(f"Certificate length: {len(crt_file)} bytes")
        logging.debug(f"Total response length: {len(response)} bytes")
        try:
            logging.debug("Headers: {}".format(b'\r\n'.join(response_headers).decode('utf-8')))
        except UnicodeDecodeError:
            logging.debug("Unable to decode headers")

        # Send response
        try:
            ssl_socket.sendall(response)
            logging.info(f"Total response sent: {len(response)} bytes")
            logging.info("Certificate sent successfully")
            return True
            
        except Exception as send_error:
            logging.error(f"Error sending response: {send_error}")
            return False

    except Exception as e:
        logging.error(f"Error handling client request: {e}")
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

def server() -> None:
    """Main server function. Sets up SSL context and handles incoming connections."""
    
    # Initialize server certificates
    download_file("ca.crt", CAConfig.CERT)
    cert_bytes = CAConfig.CERT.encode() if isinstance(CAConfig.CERT, str) else CAConfig.CERT
    key_bytes = CAConfig.KEY.encode() if isinstance(CAConfig.KEY, str) else CAConfig.KEY
    
    context = create_ca_server_ssl_context(cert_bytes, key_bytes)

    # Start server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((CAConfig.IP, CAConfig.PORT))
        server_socket.listen(5)

        logging.info(f"Server listening on {CAConfig.IP}:{CAConfig.PORT}")

        try:
            while True:
                client_socket, addr = server_socket.accept()
                logging.info(f"Client connected: {addr}")

                try:
                    with context.wrap_socket(client_socket, server_side=True) as ssl_socket:
                        handle_client_request(ssl_socket, cert_bytes, key_bytes)
                except ssl.SSLError as e:
                    logging.error(f"SSL error: {e}")
        except KeyboardInterrupt:
            logging.info("\nShutting down the server.")
        finally:
            logging.info("Server stopped.")

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    server()