"""
Unified SSL Client Module
Handles both CA certificate requests and server communication

Usage:
cd communication

python -m tls.client CA
or
python -m tls.client SERVER
"""
import traceback
import logging
import socket
import ssl
from typing import Optional, Tuple
import time
import os
from tls.protocol import CAConfig, ServerConfig, ProtocolConfig, BurpConfig, ClientConfig
from tls.utils.client import create_csr, setup_proxy_connection
from tls.utils.ca import download_file, validate_certificate, parse_http_headers

def create_client_ssl_context(use_proxy: bool = False) -> Optional[ssl.SSLContext]:
    """Create an SSL context for the client."""
    try:
        if use_proxy:  # Use proxy for SSL connection (no certificate required)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.verify_mode = ssl.CERT_NONE
            context.check_hostname = False
        else:  # Load client certificate and key
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            context.set_ciphers('AES128-SHA256')
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Load client certificate and key if available (optional)
            try:
                context.load_cert_chain(
                    certfile=ClientConfig.CLIENT_CERT_PATH,
                    keyfile=ClientConfig.CLIENT_KEY_PATH
                )
                logging.info("Client certificate and key loaded successfully")
            except FileNotFoundError:
                logging.error("Certificate files not found. Did you get them from the CA first?")
                return None
            except Exception as e:
                logging.error(f"Error loading certificates: {e}")
                return None

        return context
    except Exception as e:
        logging.error(f"Error creating SSL context: {e}")
        return None
    
class CTFClient:
    """Client for CTF challenge handling both CA and Server communication"""
    def __init__(self, use_proxy: bool = False):
        self.use_proxy = use_proxy
        self.obsv_client_random = None
        self.obsv_master_secret = None
        self.context = None
        self.secure_sock = None

    def init_ssl_context(self) -> bool:
        """Initialize SSL context based on mode"""
        self.context = create_client_ssl_context(self.use_proxy)
        return self.context is not None

    def handle_server_mode(self) -> None:
        """Handle server communication mode"""
        logging.info("=== SERVER Mode - Communicating with Server ===")
        try:
            if not self.init_ssl_context():
                logging.error("Failed to create SSL context")
                return

            self.connect_and_communicate()

        except FileNotFoundError:
            logging.error("No valid certificates found. Run in CA mode first to obtain certificates.")
        except Exception as e:
            logging.error(f"Error in SERVER mode: {e}")

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

    def connect_and_communicate(self) -> None:
        """Establish connection and communicate with server"""
        self.secure_sock = self._establish_connection(ServerConfig.IP, ServerConfig.PORT)
        if self.secure_sock:
            with self.secure_sock:
                self._communicate_with_server()
        else:
            logging.error("Failed to establish secure connection to the server.")
            logging.info("Hint: Try to check if the server responds to other types of requests...")

    def _establish_connection(self, host: str, port: int) -> Optional[ssl.SSLSocket]:
        """Establish connection to server"""
        try:
            if self.use_proxy:
                sock = socket.create_connection((BurpConfig.IP, BurpConfig.PORT))
                setup_proxy_connection(sock, host, port)
                secure_sock = self.context.wrap_socket(sock)
                logging.info(f"Connected to Burp Proxy, forwarding to {host}:{port}...")
            else:
                sock = socket.create_connection((host, port))
                sock.settimeout(ProtocolConfig.TIMEOUT)
                secure_sock = self.context.wrap_socket(sock, server_hostname=host)
                logging.info(f"Connecting to {host}:{port}...")

            logging.info(f"SSL handshake successful with {secure_sock.getpeername()}")
            return secure_sock
        except Exception as e:
            logging.error(f"Error during connection: {e}")
            traceback.print_exc()
            return None

    def _communicate_with_server(self) -> None:
        """Communicate with server after establishing connection"""
        try:
            if not os.path.exists(ClientConfig.CLIENT_CERT_PATH):
                request = "Any body home?"
                self.secure_sock.sendall(request.encode())
                logging.info("Sent: Any body home?")

                response = self.secure_sock.recv(1024).decode('utf-8')
                logging.info(f"Received: {response}")
                
                if response == "Yes, I'm here!":
                    logging.info("Server is alive! Try to reach it another way...")
                return

            logging.info(f"Handshake successful with {self.secure_sock.getpeername()}")
            logging.debug(f"Using cipher: {self.secure_sock.cipher()}")
            logging.debug(f"SSL version: {self.secure_sock.version()}")

            request = (
                f"GET /resource HTTP/1.1\r\n"
                f"Host: {ServerConfig.HOSTNAME}\r\n"
                f"\r\n"
            )
            self.secure_sock.sendall(request.encode())
            logging.info("Request sent, awaiting response...")

            response = self._receive_response()
            if response:
                self._parse_multipart_response(response)
                
        except Exception as e:
            logging.error(f"Error communicating with server: {e}")
            traceback.print_exc()

    def _receive_response(self) -> Optional[bytes]:
        """Receive response data from SSL socket"""
        response = b""
        total_received = 0
        
        while True:
            try:
                chunk = self.secure_sock.recv(1024)
                if not chunk:
                    break
                response += chunk
                total_received += len(chunk)
                logging.debug(f"Received {len(chunk)} bytes (Total: {total_received})")
            except socket.timeout:
                logging.debug("Timeout - continuing...")
                continue
            except Exception as e:
                logging.error(f"Error receiving data: {e}")
                if total_received == 0:
                    return None
                break
        
        logging.info(f"Total bytes received: {total_received}")
        return response

    def _parse_multipart_response(self, response: bytes) -> None:
        """Parse multipart response and extract encrypted messages"""
        try:
            logging.info("\n=== Encrypted Messages ===")
            parts = response.split(b'--boundary')
            
            for part in parts:
                if b'Content-Type: text/plain' in part and b'\r\n\r\n' in part:
                    message = part.split(b'\r\n\r\n', 1)[1].strip()
                    if message:
                        msg = message.decode('utf-8', errors='ignore')
                        if any(x in msg for x in ["rteng", "xasfh", "xaswp"]):
                            logging.info(f"Encrypted: {msg}")
                        elif "qjxfh" in msg:  # Session keys
                            try:
                                parts = msg.split(' ')
                                if len(parts) >= 6:
                                    self.obsv_client_random = parts[2]
                                    self.obsv_master_secret = parts[5]
                                    logging.info(f"Session Keys - Random: {self.obsv_client_random}, Master: {self.obsv_master_secret}")
                                else:
                                    logging.error("Invalid format for session keys message")
                            except Exception as e:
                                logging.error(f"Error parsing session keys: {e}")
        except Exception as e:
            logging.error(f"Error parsing response: {e}")

def main() -> None:
    """Main function handling certificate acquisition and server communication"""
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    if len(sys.argv) != 2 or sys.argv[1].upper() not in ['CA', 'SERVER']:
        print("Usage: python client.py <CA|SERVER>")
        print("  CA     - Get certificate from CA")
        print("  SERVER - Communicate with server")
        return

    mode = sys.argv[1].upper()
    use_proxy = input("Use Burp proxy? (y/n): ").lower().startswith('y')
    client = CTFClient(use_proxy)

    if mode == 'CA':
        client.handle_ca_mode()
    else:
        client.handle_server_mode()

if __name__ == "__main__":
    main()