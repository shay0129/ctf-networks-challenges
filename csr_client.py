import traceback
import logging
import socket
import ssl

from protocol import (
    CAConfig, BurpConfig,
    ClientConfig, ProtocolConfig,
    SSLConfig
)

from csr_client_utils import (
    create_client_ssl_context, 
    receive_certificate, 
    setup_proxy_connection
)
from ca_server_utils import sign_csr_with_ca, create_csr, download_file

def send_csr(secure_sock: ssl.SSLSocket, common_name: str, csr) -> bool:
    """Handle certificate exchange with the server."""
    
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
    
def client() -> None:
    """Main client function to obtain signed certificate"""
    
    logging.info("Starting client")
    context = create_client_ssl_context()
    
    # Create CSR and CA private key (this might be used for signing later)
    # Create CSR with the correct domain name
    client_csr, client_key = create_csr(
        country="IR", state="Tehran",
        city="Tehran", org_name="Sharif",
        org_unit="Cybersecurity", domain_name=ClientConfig.HOSTNAME
    )
    download_file("client.key", client_key)

    # User input to use proxy
    use_proxy = input("Use Burp proxy? (y/n): ").lower().startswith('y')
    proxy_config = (BurpConfig.HOST, BurpConfig.PORT) if use_proxy else None

    try:
        with socket.create_connection(
            proxy_config or (CAConfig.IP, CAConfig.PORT),
            timeout=ProtocolConfig.TIMEOUT
        ) as sock:
            
            if use_proxy:
                setup_proxy_connection(sock, CAConfig.IP, CAConfig.PORT)
            
            with context.wrap_socket(sock, server_hostname=CAConfig.HOSTNAME) as secure_sock:
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
        logging.info("Connection closed")

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    client()
