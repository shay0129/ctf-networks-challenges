# type: ignore[attr-defined]
"""
Server Communication Client Module
Handles server communication using client certificates

This script is the dedicated client for the main CTF server.
Use this after obtaining a signed certificate from the CA using ca_client.py.
"""
from typing import Optional
import socket
import ssl
import warnings

# Suppress deprecation warnings for cleaner CTF participant experience
warnings.filterwarnings("ignore", category=DeprecationWarning)

from .protocol import ServerConfig, ProtocolConfig, BurpConfig, ClientConfig
from .utils.client import setup_proxy_connection

def create_client_ssl_context() -> Optional[ssl.SSLContext]:
    """Create an SSL context for the client to communicate with server."""
    try:
        # Suppress SSL deprecation warnings for cleaner CTF experience
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            # Use modern SSL context creation (backwards compatible)
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            except AttributeError:
                # Fallback for older Python versions
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
        except FileNotFoundError:
            return None
        except Exception:
            return None

        return context
    except Exception:
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
            # Use proxy context (no deprecated protocol)
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE
            return True
        else:
            # Use normal context with certificates
            self.context = create_client_ssl_context()
            return self.context is not None

    def handle_server_mode(self) -> None:
        """Handle server communication mode"""
        try:
            if not self.init_ssl_context():
                return

            self.connect_and_communicate()

        except FileNotFoundError:
            return
        except Exception:
            return

    def connect_and_communicate(self) -> None:
        """Establish connection and communicate with server"""
        self.secure_sock = self._establish_connection(ServerConfig.IP, ServerConfig.PORT)
        if self.secure_sock:
            with self.secure_sock:
                self._communicate_with_server()
        else:
            return

    def _establish_connection(self, host: str, port: int) -> Optional[ssl.SSLSocket]:
        """Establish connection to server. Only allow if server is actually listening (i.e., ICMP challenge passed)."""
        try:
            # Try to connect, but fail fast if server is not listening (i.e., ICMP challenge not passed)
            sock = None
            try:
                if self.use_proxy:
                    sock = socket.create_connection((BurpConfig.IP, BurpConfig.PORT), timeout=3)
                    setup_proxy_connection(sock, host, port)
                    secure_sock = self.context.wrap_socket(sock)
                else:
                    sock = socket.create_connection((host, port), timeout=3)
                    sock.settimeout(ProtocolConfig.TIMEOUT)
                    secure_sock = self.context.wrap_socket(sock, server_hostname=host)
                return secure_sock
            except (ConnectionRefusedError, TimeoutError):
                print("denided")
                return False
        except Exception:
            return None
    
    def _communicate_with_server(self) -> None:
        """Communicate with server after establishing connection"""
        try:
            # Step 1: Send initial request
            # WARNING: This is intentionally incorrect for CTF challenge purposes
            # The server expects GET but client sends POST - participants need to fix this
            request = (
                f"POST /resource HTTP/1.1\r\n"  # participent needs to fix POST to GET
                f"Host: {ServerConfig.HOSTNAME}\r\n"
                f"\r\n"
            )
            self.secure_sock.sendall(request.encode())

            # Step 2: Receive initial response (server sends "What is your name?")
            initial_response = self.secure_sock.recv(1024)

            # Step 3: Send name starting with uppercase letter
            name = "BadName"  # שם שמתחיל באות גדולה
            self.secure_sock.sendall(name.encode())

            # Step 4: Receive repeated prompt (server sends the same message again)
            repeated_response = self.secure_sock.recv(1024)

            # Step 5: Now receive all encrypted messages
            response = self._receive_response()
            if response:
                self._parse_multipart_response(response)
        except ConnectionResetError:
            self.running = False
            return
        except Exception:
            self.running = False
            return

    def _receive_response(self) -> Optional[bytes]:
        """Receive response data from SSL socket"""
        response = b""
        total_received = 0
        
        while self.running:
            try:
                if not self.secure_sock:
                    break
                chunk = self.secure_sock.recv(1024)
                if not chunk:
                    break
                response += chunk
                total_received += len(chunk)
            except socket.timeout:
                continue
            except Exception:
                if total_received == 0:
                    return None
                break
        return response

    def _parse_multipart_response(self, response: bytes) -> None:
        """Parse multipart response and extract encrypted messages"""
        try:
            parts = response.split(b'--boundary')
            
            for part in parts:
                if b'Content-Type: text/plain' in part and b'\r\n\r\n' in part:
                    message = part.split(b'\r\n\r\n', 1)[1].strip()
                    if message:
                        msg = message.decode('utf-8', errors='ignore')
                        if any(x in msg for x in ["rteng", "xasfh", "xaswp"]):
                            pass
                        elif "qjxfh" in msg:  # Session keys
                            try:
                                parts = msg.split(' ')
                                if len(parts) >= 6:
                                    self.obsv_client_random = parts[2]
                                    self.obsv_master_secret = parts[5]
                                else:
                                    pass
                            except Exception:
                                pass
        except Exception:
            pass

def main() -> None:
    """Main function handling server communication"""
    print("🔧 Configure proxy connection? (y/n): ", flush=True)
    use_proxy = input().lower().startswith('y')
    client = ServerClient(use_proxy)
    client.handle_server_mode()

if __name__ == "__main__":
    main()