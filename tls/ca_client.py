"""
CA Certificate Client Module
Handles certificate requests from the Certificate Authority

This script is the dedicated client for the CA server (Certificate Authority).
Use this to generate a CSR, send it to the CA, and receive a signed certificate.
After running this, use server_client.py to connect to the main CTF server.
"""
from typing import Optional, Tuple
import logging
import socket
import ssl

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
        """Minimal CA mode: send CSR, receive cert, save cert, then delete key for forensics challenge."""
        # logging.info("=== CA Mode - Getting Certificate ===")
        try:
            client_csr, client_key = self._generate_csr()
            download_file(ClientConfig.CLIENT_KEY_PATH, client_key)
            # Forensics challenge: delete the key after saving (uncomment for final CTF)
            # delete_client_key(ClientConfig.CLIENT_KEY_PATH)
            if not self.init_ssl_context():
                return
            self.secure_sock = self._establish_ca_connection()
            if not self.secure_sock:
                logging.error("Failed to connect to CA server.")
                return
            with self.secure_sock:
                if not self.send_csr(client_csr):
                    logging.error("Failed to send CSR to CA.")
                    return
                if not self.receive_cert():
                    logging.error("Failed to receive certificate from CA.")
                # else:
                #     logging.info("Certificate obtained successfully.")
        except Exception as e:
            logging.error(f"Error in CA mode: {e}")

    def send_csr(self, csr: bytes) -> bool:
        """Send CSR (with padding) to CA server using HTTP POST."""
        try:
            if self.secure_sock is None:
                logging.error("No secure socket available to send CSR.")
                return False
            padding = padding_csr(len(csr))
            body = csr + padding
            # Compose minimal HTTP POST request
            request = b"POST / HTTP/1.1\r\n" + \
                      b"Host: " + CAConfig.HOSTNAME.encode() + b"\r\n" + \
                      b"Content-Length: " + str(len(body)).encode() + b"\r\n" + \
                      b"Connection: close\r\n" + \
                      b"\r\n" + \
                      body
            self.secure_sock.sendall(request)
            return True
        except Exception as e:
            logging.error(f"Error sending CSR: {e}")
            return False

    def receive_cert(self) -> bool:
        """Receive and save the certificate from the CA server."""
        try:
            if self.secure_sock is None:
                logging.error("No secure socket available to receive certificate.")
                return False
            response = b""
            self.secure_sock.settimeout(ProtocolConfig.READ_TIMEOUT * 2)
            try:
                while True:
                    chunk = self.secure_sock.recv(8192)
                    if not chunk:
                        break
                    response += chunk
            finally:
                self.secure_sock.settimeout(None)
            if not response:
                logging.error("No data received from CA for signed certificate")
                return False
            # Try to extract PEM certificate from HTTP response if present
            pem_start = response.find(b"-----BEGIN CERTIFICATE-----")
            pem_end = response.find(b"-----END CERTIFICATE-----")
            if pem_start != -1 and pem_end != -1:
                pem_end += len(b"-----END CERTIFICATE-----")
                cert_pem = response[pem_start:pem_end]
            else:
                cert_pem = response.strip()
            if not cert_pem.startswith(b"-----BEGIN CERTIFICATE-----"):
                logging.error("Received data does not look like a valid certificate.")
                logging.error(f"Raw response from CA server: {response!r}")
                return False
            with open(ClientConfig.CLIENT_CERT_PATH, 'wb') as crt_file:
                crt_file.write(cert_pem)
            # logging.info(f"Signed certificate saved to {ClientConfig.CLIENT_CERT_PATH}")
            return True
        except Exception as e:
            logging.error(f"Error receiving certificate: {e}")
            return False

    def _establish_ca_connection(self) -> Optional[ssl.SSLSocket]:
        """Establish connection to CA server"""
        try:
            if self.use_proxy:
                sock = socket.create_connection((BurpConfig.IP, BurpConfig.PORT))
                setup_proxy_connection(sock, CAConfig.IP, CAConfig.PORT)
                if self.context:
                    return self.context.wrap_socket(sock)
                logging.error("SSL context is not initialized.")
                return None
            else:
                sock = socket.create_connection((CAConfig.IP, CAConfig.PORT))
                sock.settimeout(ProtocolConfig.TIMEOUT)
                if self.context:
                    return self.context.wrap_socket(sock, server_hostname=CAConfig.HOSTNAME)
                logging.error("SSL context is not initialized.")
                return None
        except Exception as e:
            logging.error(f"Failed to connect to CA: {e}")
            return None
    
    def _generate_csr(self) -> Tuple[bytes, bytes]:
        """Generate CSR and client key using the cryptography library"""
        # logging.info("Generating CSR...")
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.x509.oid import NameOID
        from cryptography import x509
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        # WARNING: Organization and Common Name are intentionally set to "None" for CTF challenge
        # Participants must use Burp proxy to intercept and modify the CSR before it's sent to CA
        # The server expects Organization="Sharif University of Technology" and Common Name="Shay"
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Tehran"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Tehran"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "None"),  # Should be 'Sharif University of Technology'
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Cybersecurity Department"),
            x509.NameAttribute(NameOID.COMMON_NAME, "None"),  # Should be client name
        ])).sign(private_key, hashes.SHA512())
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        return csr_pem, private_key_pem

def main() -> None:
    """Main function handling certificate acquisition from CA"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    print("🔧 Configure proxy connection? (y/n): ", flush=True)
    use_proxy = input().lower().startswith('y')
    client = CAClient(use_proxy)
    client.handle_ca_mode()

if __name__ == "__main__":
    main()