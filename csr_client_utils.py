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

from typing import Tuple, Optional, Dict
from socket import socket, error as SocketError
import logging
import time 
import ssl
import re



def parse_http_headers(raw_data: bytes) -> Tuple[Optional[Dict[bytes, bytes]], bytes, Optional[int]]:
    try:
        # Split headers and body
        header_part, body = raw_data.split(b'\r\n\r\n', 1)
        
        # Split header lines
        header_lines = header_part.split(b'\r\n')
        
        headers = {}
        for line in header_lines[1:]:
            if b':' in line:
                key, value = line.split(b':', 1)
                headers[key.strip().lower()] = value.strip()
        
        # Get Content-Length
        content_length = None
        if b'content-length' in headers:
            try:
                content_length = int(headers[b'content-length'])
            except ValueError:
                pass
        
        return headers, body, content_length
    
    except Exception as e:
        logging.error(f"Error parsing HTTP headers: {e}")
        return None, b"", None

def validate_certificate(cert_data: bytes) -> bool:
    """Validate certificate format."""

    return (cert_data.startswith(b'-----BEGIN CERTIFICATE-----') and 
            cert_data.endswith(b'-----END CERTIFICATE-----\n'))


def setup_proxy_connection(sock: socket, server_ip: str, server_port: int) -> None:
    """Setup proxy tunnel connection with better error handling and debugging"""
    
    connect_request = (
        f"CONNECT {server_ip}:{server_port} HTTP/1.1\r\n"
        f"Host: {server_ip}:{server_port}\r\n"
        f"User-Agent: PythonProxy\r\n"
        f"Proxy-Connection: keep-alive\r\n\r\n"
    ).encode()
    
    logging.debug(f"Sending proxy CONNECT request: {connect_request}")
    sock.sendall(connect_request)
    
    response = b""
    while b"\r\n\r\n" not in response:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed by proxy") 
            response += chunk
            logging.debug(f"Received from proxy: {chunk}")
        except socket.timeout:
            raise ConnectionError("Proxy connection timeout")
    
    logging.debug(f"Complete proxy response: {response}")
    
    if not response.startswith(b"HTTP/1.1 200"):
        raise ConnectionError(f"Proxy connection failed: {response.decode()}")
    
    logging.info("Proxy tunnel established successfully")