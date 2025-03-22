"""
CA Certificate Client Module
Handles certificate requests from the Certificate Authority
"""
import sys
sys.path.append('C:\\my-CTF\\communication')

import logging
import socket
import ssl
from typing import Optional, Tuple
import time
import os
from tls.protocol import CAConfig, ProtocolConfig, BurpConfig, ClientConfig
from tls.utils.client import create_csr, setup_proxy_connection

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
    
class CAClient:
    """Client for handling Certificate Authority communication"""
    def __init__(self, use_proxy: bool = False):
        self.use_proxy = use_proxy
        self.context = None
        self.secure_sock = None

    def init_ssl_context(self) -> bool:
        """Initialize SSL context for CA communication"""
        self.context = create_client_ssl_context(self.use_proxy)
        return self.context is not None

    def handle_ca_mode(self) -> None:
        """Handle CA communication mode"""
        logging.info("=== CA Mode - Getting Certificate ===")
        try:
            # Generate CSR
            client_csr, client_key = self._generate_csr()
            with open(ClientConfig.CLIENT_KEY_PATH, 'wb') as key_file:
                key_file.write(client_key)
            logging.info(f"Client key saved to {ClientConfig.CLIENT_KEY_PATH}")
            
            if not self.init_ssl_context():
                return

            # Connect to CA
            self.secure_sock = self._establish_ca_connection()
            if self.secure_sock:
                with self.secure_sock:
                    self._handle_ca_communication(client_csr)

        except Exception as e:
            logging.error(f"Error in CA mode: {e}")

    def _establish_ca_connection(self) -> Optional[ssl.SSLSocket]:
        """Establish connection to CA server"""
        try:
            if self.use_proxy:
                sock = socket.create_connection((BurpConfig.IP, BurpConfig.PORT))
                setup_proxy_connection(sock, CAConfig.IP, CAConfig.PORT)
                return self.context.wrap_socket(sock)
            else:
                sock = socket.create_connection((CAConfig.IP, CAConfig.PORT))
                sock.settimeout(ProtocolConfig.TIMEOUT)
                return self.context.wrap_socket(sock, server_hostname=CAConfig.HOSTNAME)
        except Exception as e:
            logging.error(f"Failed to connect to CA: {e}")
            return None

    def _generate_csr(self) -> Tuple[bytes, bytes]:
        """Generate CSR and client key"""
        logging.info("Generating CSR...")
        return create_csr(
            country="IR", 
            state="Tehran",
            city="Tehran",
            org_name="Sharif", 
            org_unit="Cybersecurity",
            domain_name=ClientConfig.HOSTNAME_REQUESTED
        )

    def _handle_ca_communication(self, client_csr: bytes) -> None:
        """Handle communication with CA server"""
        if self._send_csr_request(client_csr):
            time.sleep(2)
            if self._get_signed_certificate():
                logging.info("Certificate obtained successfully")

    def _send_csr_request(self, csr: bytes) -> bool:
        """Send CSR request to CA server"""
        try:
            http_request = (
                f"POST /sign_csr HTTP/1.1\r\n"
                f"Host: {CAConfig.HOSTNAME}\r\n"
                f"Content-Length: {len(csr)}\r\n"
                f"Content-Type: application/x-pem-file\r\n\r\n"
            ).encode() + csr
            
            self.secure_sock.sendall(http_request)
            logging.info("CSR sent successfully")
            return True
        except Exception as e:
            logging.error(f"Error sending CSR request: {e}")
            return False

    def _get_signed_certificate(self) -> bool:
        """Receive the signed certificate from the CA server and save it to a file"""
        try:
            crt_data = b""
            while True:
                chunk = self.secure_sock.recv(8192)
                if not chunk:
                    break
                crt_data += chunk

            if len(crt_data) == 0:
                logging.error("No data received for signed certificate")
                return False
            
            with open(ClientConfig.CLIENT_CERT_PATH, 'wb') as crt_file:
                crt_file.write(crt_data)
            
            logging.info(f"Signed certificate saved to {ClientConfig.CLIENT_CERT_PATH}")
            return True
        
        except Exception as e:
            logging.error(f"Error receiving signed certificate: {e}")
            return False

def main() -> None:
    """Main function handling certificate acquisition from CA"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    use_proxy = input("Use Burp proxy? (y/n): ").lower().startswith('y')
    client = CAClient(use_proxy)
    client.handle_ca_mode()

if __name__ == "__main__":
    main()