"""
CSR Client Implementation
Handles certificate signing request generation and communication with CA server.
"""
import traceback
import logging
import socket
import ssl
import time
from typing import Optional

from protocol import (
    CAConfig, BurpConfig,
    ClientConfig, ProtocolConfig
)
from client_utils import (
    setup_proxy_connection,
    parse_http_headers,
    validate_certificate
)
from ca_server_utils import (
    sign_csr_with_ca,
    create_csr,
    download_file
)

def create_client_ssl_context(use_proxy: bool = False) -> ssl.SSLContext:
    """
    Create SSL context with appropriate security settings.
    
    Args:
        use_proxy: Whether to use proxy-compatible settings
        
    Returns:
        Configured SSL context
    """
    if use_proxy:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.verify_mode = ssl.CERT_NONE
        context.check_hostname = False
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.set_ciphers('AES128-SHA256')
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    
    return context

def send_csr(secure_sock: ssl.SSLSocket, common_name: str, csr: bytes) -> bool:
    """
    Send CSR to CA server and handle response.
    
    Args:
        secure_sock: Established SSL socket
        common_name: Certificate common name
        csr: Certificate signing request data
        
    Returns:
        True if certificate received successfully, False otherwise
    """
    http_request = (
        f"POST /sign_csr HTTP/1.1\r\n"
        f"Host: {CAConfig.HOSTNAME}\r\n" 
        f"Content-Length: {len(csr)}\r\n"
        f"Content-Type: application/x-pem-file\r\n\r\n"
    ).encode() + csr
    
    secure_sock.sendall(http_request)
    logging.info("CSR sent successfully")
    
    crt_file = receive_certificate(secure_sock, timeout=ProtocolConfig.TIMEOUT, debug=True)
    
    if crt_file:
        logging.info("Received certificate from server")
        download_file("client.crt", crt_file)
        return True
    else:
        logging.error("Failed to receive certificate")
        return False

def receive_certificate(secure_sock: ssl.SSLSocket, timeout: int = 30, debug: bool = False) -> Optional[bytes]:
    """
    Receive signed certificate from CA server.
    
    Args:
        secure_sock: Established SSL socket
        timeout: Socket timeout in seconds
        debug: Enable debug logging
        
    Returns:
        Certificate data if valid, None otherwise
    """
    try:
        secure_sock.settimeout(timeout)
        response = b""
        content_length = None
        headers_complete = False
        
        while True:
            chunk = secure_sock.recv(8192)
            if not chunk:
                break
                
            response += chunk
            
            if not headers_complete and b'\r\n\r\n' in response:
                headers, body, content_length = parse_http_headers(response)
                if headers is not None:
                    headers_complete = True
                    
                    if content_length is None:
                        logging.error("Invalid or missing Content-Length")
                        return None
            
            if headers_complete and len(response) >= content_length + len(response) - len(body):
                _, body = response.split(b'\r\n\r\n', 1)
                if validate_certificate(body):
                    return body
                return None
                
    except Exception as e:
        logging.error(f"Error in receive_certificate: {e}")
        return None

def client() -> None:
    """
    Main client function to obtain signed certificate.
    Handles connection setup, CSR generation, and certificate retrieval.
    """
    logging.info("Starting client")
    
    use_proxy = input("Use Burp proxy? (y/n): ").lower().startswith('y')
    context = create_client_ssl_context(use_proxy)
    
    client_csr, client_key = create_csr(
        country="IR", 
        state="Tehran",
        city="Tehran", 
        org_name="Sharif",
        org_unit="Cybersecurity", 
        domain_name=ClientConfig.HOSTNAME
    )
    download_file("client.key", client_key)

    try:
        if use_proxy:
            sock = socket.create_connection((BurpConfig.HOST, BurpConfig.PORT))
            setup_proxy_connection(sock, CAConfig.IP, CAConfig.PORT)
            secure_sock = context.wrap_socket(sock)
        else:
            sock = socket.create_connection((CAConfig.IP, CAConfig.PORT))
            secure_sock = context.wrap_socket(sock, server_hostname=CAConfig.HOSTNAME)
        
        with secure_sock:
            logging.info(f"SSL connection established with {secure_sock.getpeername()}")
            logging.debug(f"Using cipher: {secure_sock.cipher()}")
            secure_sock.settimeout(ProtocolConfig.TIMEOUT)
            
            success = send_csr(secure_sock, ClientConfig.HOSTNAME, client_csr)
            if not success:
                logging.error("Certificate exchange failed")
                
    except Exception as e:
        logging.error(f"Connection error: {e}")
        traceback.print_exc()
    finally:
        if 'secure_sock' in locals() and secure_sock:
            secure_sock.close()
        logging.info("Connection closed")

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    client()