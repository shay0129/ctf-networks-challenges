"""
SSL Certificate Utility Functions
This module provides utilities for handling SSL certificates, keys and connections.
Includes functions for certificate generation, validation and communication.
"""
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography import x509

from typing import Tuple, Optional
from socket import socket, error as SocketError
import logging
import time 
import ssl
import re

def create_client_ssl_context() -> ssl.SSLContext:
    """Create an SSL context for the client."""

    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.set_ciphers('AES128-SHA256')
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def parse_http_headers(response_data: bytes) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    """Parse HTTP headers and return headers, body and content length."""
    try:
        response_str = response_data.decode('utf-8', errors='replace')
        headers, body = None, None
        
        if '\r\n\r\n' in response_str:
            headers, body = response_str.split('\r\n\r\n', 1)
        elif '\n\n' in response_str:
            headers, body = response_str.split('\n\n', 1)
        else:
            return None, None, None

        content_length = None
        if headers:
            try:
                match = re.search(r'Content-Length:\s*(\d+)', headers)
                if match:
                    content_length = int(match.group(1))
                else:
                    content_length = int(headers.split("Content-Length:")[1].split("\n")[0].strip())
            except (AttributeError, IndexError, ValueError):
                return headers, body, None
                
        return headers, body, content_length
        
    except Exception as e:
        logging.error(f"Error parsing HTTP response: {e}")
        return None, None, None


def validate_certificate(cert_data: bytes) -> bool:
    """Validate certificate format."""

    return (cert_data.startswith(b'-----BEGIN CERTIFICATE-----') and 
            cert_data.endswith(b'-----END CERTIFICATE-----\n'))


def receive_certificate(secure_sock: ssl.SSLSocket, timeout: int = 30, debug: bool = False) -> Optional[bytes]:
    try:
        secure_sock.settimeout(timeout)
        full_response = b""
        total_received = 0

        while True:
            try:
                chunk = secure_sock.recv(8192)
                if not chunk:
                    logging.info("Connection closed by server")
                    break
                    
                full_response += chunk
                total_received += len(chunk)
                
                if debug:
                    logging.debug(f"Received {len(chunk)} bytes. Total: {total_received}")

                headers, body, content_length = parse_http_headers(full_response)
                
                if headers is None:
                    continue
                    
                if content_length is None:
                    logging.error("Invalid or missing Content-Length")
                    return None
                    
                body_bytes = body.encode('utf-8')
                if len(body_bytes) < content_length:
                    continue
                    
                if len(body_bytes) == content_length:
                    if validate_certificate(body_bytes):
                        logging.info(f"Valid certificate received ({len(body_bytes)} bytes)")
                        return body_bytes
                    else:
                        logging.error("Invalid certificate format")
                        return None
                else:
                    logging.error("Response body length mismatch")
                    return None
                    
            except ssl.SSLWantReadError:
                time.sleep(0.1)
                continue
            # Change this line
            except TimeoutError:  # built-in TimeoutError
                logging.warning("Socket timeout")
                break
            except Exception as e:
                logging.error(f"Error receiving data: {e}")
                break
                
    except Exception as e:
        logging.error(f"Fatal error in receive_certificate: {e}")
        
    return None

def setup_proxy_connection(sock:ssl.SSLSocket, server_ip: str, server_port: int) -> None:
    """Setup proxy tunnel connection"""

    connect_request = (
        f"CONNECT {server_ip}:{server_port} HTTP/1.1\r\n"
        f"Host: {server_ip}:{server_port}\r\n\r\n"
    ).encode()
    
    sock.sendall(connect_request)
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Proxy connection failed") 
        response += chunk
        
    if not response.startswith(b"HTTP/1.1 200"):
        raise ConnectionError(f"Proxy connection failed: {response.decode()}")
