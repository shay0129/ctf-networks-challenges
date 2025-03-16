"""Client utilities."""
from typing import Tuple
from socket import socket
from OpenSSL import crypto
import logging

def create_csr(country: str, state: str, city: str, org_name: str, 
               org_unit: str, domain_name: str) -> Tuple[bytes, bytes]:
    """Create Certificate Signing Request."""
    """
    Create a Certificate Signing Request (CSR) and private key.

    Args:
        country: Country code (e.g., 'US')
        state: State or province
        city: City or locality
        org_name: Organization name
        org_unit: Organizational unit name
        domain_name: Common name (domain name)

    Returns:
        Tuple containing CSR and private key in PEM format
    """
    private_key = crypto.PKey()
    private_key.generate_key(crypto.TYPE_RSA, 4096)

    csr = crypto.X509Req()
    subject = csr.get_subject()
    subject.C = country
    subject.ST = state
    subject.L = city
    subject.O = org_name
    subject.OU = org_unit
    subject.CN = domain_name

    csr.set_pubkey(private_key)
    csr.sign(private_key, 'sha512')

    csr_pem = crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr)
    private_key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key)

    return csr_pem, private_key_pem
    
"""Proxy communication utilities."""
import socket
import logging

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