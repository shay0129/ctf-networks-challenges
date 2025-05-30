"""
Server Communication Client Module
Handles server communication using client certificates
"""
from typing import Optional
import traceback
import logging
import socket
import ssl

from .protocol import ServerConfig, ProtocolConfig, BurpConfig, ClientConfig
from .utils.client import setup_proxy_connection

def create_client_ssl_context() -> Optional[ssl.SSLContext]:
    """Create an SSL context for the client to communicate with server."""
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.set_ciphers('AES128-SHA256')
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Load client certificate and key
        try:
            context.load_cert_chain(
                certfile=ClientConfig.CLIENT_CERT_PATH,
                keyfile=ClientConfig.CLIENT_KEY_PATH
            )
            logging.info("Loaded")
        except FileNotFoundError:
            logging.error("Certificate files not found.")
            return None
        except Exception as e:
            logging.error(f"Error loading certificates: {e}")
            return None

        return context
    except Exception as e:
        logging.error(f"Error creating SSL context: {e}")
        return None
    
class ServerClient:
    """Client for communicating with the server using client certificates"""
    def __init__(self, use_proxy: bool = False):
        self.use_proxy = use_proxy
        self.obsv_client_random = None
        self.obsv_master_secret = None
        self.context = None
        self.secure_sock = None
        self.running = True

    def init_ssl_context(self) -> bool:
        """Initialize SSL context for server communication"""
        if self.use_proxy:
            # Use proxy context
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            self.context.verify_mode = ssl.CERT_NONE
            self.context.check_hostname = False
            return True
        else:
            # Use normal context with certificates
            self.context = create_client_ssl_context()
            return self.context is not None

    def handle_server_mode(self) -> None:
        """Handle server communication mode"""
        try:
            if not self.init_ssl_context():
                logging.error("Failed to create SSL context")
                return

            self.connect_and_communicate()

        except FileNotFoundError:
            logging.error("No valid certificates found.")
        except Exception as e:
            logging.error(f"Error in SERVER mode: {e}")
            traceback.print_exc()

    def connect_and_communicate(self) -> None:
        """Establish connection and communicate with server"""
        self.secure_sock = self._establish_connection(ServerConfig.IP, ServerConfig.PORT)
        if self.secure_sock:
            with self.secure_sock:
                self._communicate_with_server()
        else:
            logging.error("Failed to establish secure connection to the server.")

    def _establish_connection(self, host: str, port: int) -> Optional[ssl.SSLSocket]:
        """Establish connection to server"""
        try:
            if self.use_proxy:
                sock = socket.create_connection((BurpConfig.IP, BurpConfig.PORT))
                setup_proxy_connection(sock, host, port)
                secure_sock = self.context.wrap_socket(sock)  # type: ignore[attr-defined]
                logging.info(f"Connected to Burp Proxy, forwarding to {host}:{port}...")
            else:
                sock = socket.create_connection((host, port))
                sock.settimeout(ProtocolConfig.TIMEOUT)
                secure_sock = self.context.wrap_socket(sock, server_hostname=host)  # type: ignore[attr-defined]
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
            logging.info(f"Handshake successful with {self.secure_sock.getpeername()}")  # type: ignore[attr-defined]
            logging.debug(f"Using cipher: {self.secure_sock.cipher()}")  # type: ignore[attr-defined]
            logging.debug(f"SSL version: {self.secure_sock.version()}")  # type: ignore[attr-defined]

            # Step 1: Send initial request
            logging.info("Sending initial request to server...")
            request = (
                f"G /resource HTTP/1.1\r\n" # participent needs to fix G to GET
                f"Host: {ServerConfig.HOSTNAME}\r\n"
                f"\r\n"
            )
            self.secure_sock.sendall(request.encode())  # type: ignore[attr-defined]
            logging.info("Initial request sent, awaiting response...")

            # שלב 2: קבל את הודעת "What is your name?"
            initial_response = self.secure_sock.recv(1024)  # type: ignore[attr-defined]
            logging.info(f"Initial response: {initial_response.decode('utf-8', errors='ignore')}")

            # שלב 3: שלח שם שמתחיל באות גדולה
            name = "BadName"  # שם שמתחיל באות גדולה
            logging.info(f"Sending name: {name}")
            self.secure_sock.sendall(name.encode())  # type: ignore[attr-defined]

            # שלב 4: קבל את התגובה החוזרת (השרת שולח שוב את אותה הודעה)
            repeated_response = self.secure_sock.recv(1024)  # type: ignore[attr-defined]
            logging.info(f"Repeated prompt: {repeated_response.decode('utf-8', errors='ignore')}")

            # שלב 5: כעת קבל את כל ההודעות המוצפנות
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
        
        while self.running:
            try:
                if not self.secure_sock:
                    break
                chunk = self.secure_sock.recv(1024)  # type: ignore[attr-defined]
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
    """Main function handling server communication"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    use_proxy = input("Use Burp proxy? (y/n): ").lower().startswith('y')
    client = ServerClient(use_proxy)
    client.handle_server_mode()

if __name__ == "__main__":
    main()