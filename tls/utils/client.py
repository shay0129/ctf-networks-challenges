"""Client utilities."""
from typing import Optional
from socket import socket
import logging
import ssl

from ..protocol import PADDING_MARKER

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

def create_client_ssl_context(use_proxy: bool = False) -> Optional[ssl.SSLContext]:
    """Create an SSL context for the client."""
    try:
        if use_proxy:  # Use proxy for SSL connection (no certificate required)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.verify_mode = ssl.CERT_NONE
            context.check_hostname = False
        else:  # Create basic context for CA communication
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            context.set_ciphers('AES128-SHA256')
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        return context
    except Exception as e:
        logging.error(f"Error creating SSL context: {e}")
        return None

def padding_csr(csr_len: int) -> bytes:
    return f"\n{PADDING_MARKER}{csr_len:05d}".encode()