"""
CA Certificate Client Module
Handles certificate requests from the Certificate Authority
"""
from typing import Optional, Tuple
import traceback
import logging
import socket
import ssl
import time

from OpenSSL import crypto

from .protocol import CAConfig, ProtocolConfig, BurpConfig, ClientConfig
from .utils.client import setup_proxy_connection, create_client_ssl_context, padding_csr
from .utils.ca import download_file

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
            download_file(ClientConfig.CLIENT_KEY_PATH, client_key)
            
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

        # Generate private key and CSR
        # Note: In a real-world scenario, you would use a secure method to generate and store the private key.
        private_key = crypto.PKey()
        private_key.generate_key(crypto.TYPE_RSA, 4096)

        csr = crypto.X509Req()
        subject = csr.get_subject()
        subject.C = "IR" # Country Name
        subject.ST = "Tehran" # State or Province Name
        subject.L = "Tehran" ## Locality Name
        subject.O = "None" # Organization Name, have to be 'Sharif University of Technology'
        subject.OU = "Cybersecurity Department" # Organizational Unit Name
        subject.CN = "None" # Common Name/Domain Name, have to be Client Name
        
        csr.set_pubkey(private_key)
        csr.sign(private_key, 'sha512')

        csr_pem = crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr) # Convert CSR to PEM format
        private_key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key) # Convert private key to PEM format

        return csr_pem, private_key_pem

    def _handle_ca_communication(self, client_csr: bytes) -> None:
        """Handle communication with CA server"""
        if self._send_csr_request(client_csr):
            time.sleep(2)
            if self._get_signed_certificate():
                logging.info("Certificate obtained successfully")

    def _send_csr_request(self, csr: bytes) -> bool:
        """Send CSR request to CA server"""
        try:
            padding = padding_csr(len(csr))  # Ensure padding is correct
            http_request = (
                f"POST /sign_csr HTTP/1.1\r\n"
                f"Host: {CAConfig.HOSTNAME}\r\n"
                f"Content-Length: {len(csr) + len(padding)}\r\n"  # Important to include padding length
                f"Content-Type: application/x-pem-file\r\n\r\n"
            ).encode() + csr + padding

            self.secure_sock.sendall(http_request)
            logging.info("CSR sent successfully")
            return True
        except Exception as e:
            logging.error(f"Error sending CSR request: {e}")
            return False
    
    def _get_signed_certificate(self) -> bool:
        """Receive the signed certificate from the CA server, parse HTTP, and save it."""
        try:
            response = b""
            # Set a reasonable timeout for reading the response
            self.secure_sock.settimeout(ProtocolConfig.READ_TIMEOUT * 2)
            while True:
                chunk = self.secure_sock.recv(8192) # Read larger chunks
                if not chunk:
                    break # Connection closed by server/proxy
                response += chunk
            self.secure_sock.settimeout(None) # Reset timeout

            if not response:
                logging.error("No data received from CA/Proxy for signed certificate")
                return False

            # --- HTTP Response Parsing ---
            if b"\r\n\r\n" in response:
                headers_part, body_data = response.split(b"\r\n\r\n", 1)
                headers_str = headers_part.decode('utf-8', errors='ignore')
                logging.debug(f"Received CA/Proxy headers:\n{headers_str}")

                # Check HTTP status code
                if "HTTP/1.1 200 OK" not in headers_str.splitlines()[0]:
                    logging.error(f"Received non-OK status from CA/Proxy: {headers_str.splitlines()[0]}")
                    logging.error(f"Response Body (potential error message):\n{body_data.decode('utf-8', errors='ignore')}")
                    # DO NOT SAVE THIS BODY AS CERTIFICATE
                    return False

                # Check if the body looks like a certificate (basic check)
                if not body_data.strip().startswith(b"-----BEGIN CERTIFICATE-----"):
                    logging.error("Received data body does not look like a valid certificate.")
                    logging.debug(f"Received Body:\n{body_data.decode('utf-8', errors='ignore')}")
                    # DO NOT SAVE THIS BODY AS CERTIFICATE
                    return False

                # --- Save ONLY the valid certificate body ---
                try:
                    with open(ClientConfig.CLIENT_CERT_PATH, 'wb') as crt_file:
                        crt_file.write(body_data)
                    logging.info(f"Signed certificate saved to {ClientConfig.CLIENT_CERT_PATH}")
                    return True
                except Exception as e:
                    logging.error(f"Failed to write certificate file: {e}")
                    return False
            else:
                # If no \r\n\r\n, it's likely not a valid HTTP response
                logging.error("Invalid response format received - missing \\r\\n\\r\\n separator.")
                logging.debug(f"Received raw data:\n{response.decode('utf-8', errors='ignore')}")
                return False

        except socket.timeout:
            logging.error("Timeout waiting for certificate data from CA/Proxy.")
            return False
        except Exception as e:
            logging.error(f"Error receiving or processing signed certificate response: {e}")
            #traceback.print_exc()
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