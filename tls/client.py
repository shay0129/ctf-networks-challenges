"""
Unified SSL Client Module
Handles communication with Server.
"""
from typing import Optional
import logging
import socket
import ssl

from .protocol import ServerConfig, ProtocolConfig, BurpConfig, ClientConfig
from .utils.client import setup_proxy_connection

def create_client_ssl_context(use_proxy: bool = False) -> Optional[ssl.SSLContext]:
    """Create an SSL context for the client.
    Added option to load self-signed server certificate (client not verify server cert), for CTF needs.
    """
    try:
        if use_proxy:  # Use proxy for SSL connection (no certificate required)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.verify_mode = ssl.CERT_NONE
            context.check_hostname = False
        else:  # Load client certificate and key
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
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
        self.running = True

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
            #traceback.print_exc()

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
                setup_proxy_connection(sock, host, port) # Sends the CONNECT request to the proxy
                sock.settimeout(ProtocolConfig.TIMEOUT) # Set timeout for the socket

                # Wrap the socket with SSL (wrap is a blocking call, so it will wait for the handshake)
                # Note: The proxy will handle the SSL handshake with the server
                if self.context is not None:
                    secure_sock = self.context.wrap_socket(sock)  # type: ignore[attr-defined]
                else:
                    logging.error("SSL context is not initialized.")
                    return None
                logging.info(f"Connected to Burp Proxy, forwarding to {host}:{port}...")
            else:
                sock = socket.create_connection((host, port))
                sock.settimeout(ProtocolConfig.TIMEOUT)
                if self.context is not None:
                    secure_sock = self.context.wrap_socket(sock, server_hostname=host)  # type: ignore[attr-defined]
                else:
                    logging.error("SSL context is not initialized.")
                    return None
                logging.info(f"Connecting to {host}:{port}...")

            logging.info(f"SSL handshake successful with {secure_sock.getpeername()}")
            return secure_sock
        except Exception as e:
            logging.error(f"Error during connection: {e}")
            return None

    def _communicate_with_server(self) -> None:
        """Communicate with server after establishing connection"""
        if self.secure_sock is None:
            logging.error("Secure socket is not initialized.")
            return
        try:
            # Step 1: Send initial GET request
            request = (
                f"GET /resource HTTP/1.1\r\n" # need to fix POST to GET
                f"Host: {ServerConfig.HOSTNAME}\r\n"
                f"\r\n"
            )
            self.secure_sock.sendall(request.encode())  # type: ignore[attr-defined]
            logging.info("Client: Initial request sent, awaiting response...")

            # Step 2: Receive initial response (server sends "What is your name?")
            initial_response = self.secure_sock.recv(1024)  # type: ignore[attr-defined]
            logging.info(f"Initial response: {initial_response.decode('utf-8', errors='ignore')}")

            # Step 3: Send name starting with uppercase letter
            name = "Shay"  # Example name, should start with uppercase letter  
            self.secure_sock.sendall(name.encode())  # type: ignore[attr-defined]

            # Step 4: Receive repeated prompt (server sends the same message again)
            repeated_response = self.secure_sock.recv(1024)  # type: ignore[attr-defined]
            logging.info(f"Repeated prompt: {repeated_response.decode('utf-8', errors='ignore')}")

            # Step 5: Now receive all encrypted messages
            response = self._receive_response()
            if response:
                self._parse_multipart_response(response)
                
        except Exception as e:
            logging.error(f"Error communicating with server: {e}")
            #traceback.print_exc()

    def _receive_response(self) -> Optional[bytes]:
        """Receive response data from SSL socket"""
        if self.secure_sock is None:
            logging.error("Secure socket is not initialized.")
            return None
        response = b""
        total_received = 0
        self.secure_sock.settimeout(ProtocolConfig.READ_TIMEOUT)  # type: ignore[attr-defined]
        try:
            while True:
                chunk = self.secure_sock.recv(4096)  # type: ignore[attr-defined]
                if not chunk:
                    break  # Server closed the connection
                response += chunk
                total_received += len(chunk)
                logging.debug(f"Received {len(chunk)} bytes (Total: {total_received})")
        except socket.timeout:
            logging.warning("Socket timeout while receiving data.")
            # Decide if returning partial response is useful
        except Exception as e:
            logging.error(f"Error receiving data: {e}")
            return None

        logging.info(f"Total bytes received: {total_received}")
        return response if total_received > 0 else None

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
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    print("Use Burp proxy? (y/n): ", flush=True)
    use_proxy = input().lower().startswith('y')
    client = CTFClient(use_proxy)

    client.handle_server_mode()

if __name__ == "__main__":
    main()