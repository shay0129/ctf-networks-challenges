"""
Client utility functions for CSR operations.
Includes proxy setup, HTTP parsing, and certificate validation.
"""
from typing import Tuple, Optional, Dict
from socket import socket, error as SocketError
import logging

def parse_http_headers(raw_data: bytes) -> Tuple[Optional[Dict[bytes, bytes]], bytes, Optional[int]]:
    """
    Parse HTTP headers from raw data.
    
    Args:
        raw_data: Raw HTTP request/response data
        
    Returns:
        Tuple containing:
        - Dictionary of headers (or None if parsing fails)
        - Body content
        - Content length if specified
    """
    try:
        header_part, body = raw_data.split(b'\r\n\r\n', 1)
        header_lines = header_part.split(b'\r\n')
        
        headers = {}
        for line in header_lines[1:]:
            if b':' in line:
                key, value = line.split(b':', 1)
                headers[key.strip().lower()] = value.strip()
        
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
    """
    Validate certificate PEM format.
    
    Args:
        cert_data: Certificate data in bytes
        
    Returns:
        True if certificate format is valid, False otherwise
    """
    return (cert_data.startswith(b'-----BEGIN CERTIFICATE-----') and 
            cert_data.endswith(b'-----END CERTIFICATE-----\n'))

def setup_proxy_connection(sock: socket, server_ip: str, server_port: int) -> None:
    """
    Setup proxy tunnel connection with error handling.
    
    Args:
        sock: Socket object
        server_ip: Target server IP
        server_port: Target server port
        
    Raises:
        ConnectionError: If proxy connection fails
    """
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
    
    if not response.startswith(b"HTTP/1.1 200"):
        raise ConnectionError(f"Proxy connection failed: {response.decode()}")
    
    logging.info("Proxy tunnel established successfully")