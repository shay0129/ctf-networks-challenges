"""
Server Implementation Module
Implements sequential CTF challenges starting with ICMP


Usage:
- Run the server script to start the server
cd C:\my-CTF
C:\my-CTF\venv\Scripts\python.exe communication\tls\server.py

- The server will run the ICMP challenge first
- After the ICMP challenge is completed, the server will initialize and run the main server components
- The server will listen for client connections and handle requests
- The server will print the encryption key after a delay
"""
import sys
sys.path.append('C:\\my-CTF\\communication')

import logging
import socket
import select
import time
import threading
from typing import List, Optional
import ssl
from tls.protocol import ServerConfig, ProtocolConfig, SSLConfig
from tls.utils.server import handle_ssl_request, _temp_cert_to_context
from tls.server_challenges.icmp_challenge import start_icmp_server
from tls.server_challenges.ca_challenge import CAChallenge
from tls.server_challenges.image_challenge import ImageChallenge
import subprocess

class CTFServer:
    """Main CTF server managing all challenges sequentially"""
    def __init__(self):
        self.running = True
        self.icmp_completed = False
        self.ca_challenge = CAChallenge()
        self.image_challenge = ImageChallenge()
        self.server_socket: Optional[socket.socket] = None
        self.context: Optional[ssl.SSLContext] = None
        self.client_random = None
        self.master_secret = None
        self.logger = logging.getLogger('server')

    def run(self) -> None:
        """Run the server challenges in sequence"""
        try:
            # First run ICMP challenge to completion
            self.run_icmp_challenge()
            
            # Wait for ICMP challenge completion before proceeding
            while not self.icmp_completed:
                time.sleep(1)  # Check every second to ensure ICMP is completed

            # Then initialize and run main server components
            self.initialize()
            self._handle_server_loop()
            
        except KeyboardInterrupt:
            self.running = False
            self.logger.info("Server shutdown requested")
        finally:
            self.cleanup()

    def run_icmp_challenge(self) -> None:
        """Run ICMP challenge to completion"""
        self.logger.info("Starting ICMP Challenge phase...")
        try:
            # Run ICMP challenge in main thread
            start_icmp_server()
            self.icmp_completed = True
            self.logger.info("ICMP Challenge completed successfully")
        except Exception as e:
            self.logger.error(f"Error in ICMP challenge: {e}")
            raise

    def run_ca_challenge(self):
        self.logger.info("Starting CA Challenge...")
        ca_process = subprocess.Popen(["python", "server_challenges/ca_challenge.py"], cwd="communication/tls")
        ca_process.wait()
        self.logger.info("CA Challenge completed.")

    # def prepare_for_client(self):
    #     self.logger.info("Preparing to accept client with signed certificate...")
        
    #     # Load the server's SSL context with the necessary certificates and keys
    #     self.context = create_server_ssl_context(ServerConfig.CERT, ServerConfig.KEY)
        
    #     # Bind the server socket to the appropriate IP and port
    #     self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #     self.server_socket.bind((ServerConfig.IP, ServerConfig.PORT))
    #     self.server_socket.listen(ProtocolConfig.MAX_CONNECTIONS)
        
    #     self.logger.info("Server ready to accept client connections.")
        
    def initialize(self) -> None:
        """Initialize server components after ICMP challenge"""
        self.logger.info("Initializing main server components...")
        # Get session data
        self.client_random, self.master_secret = self.image_challenge.extract_ssl_info()
        
        # Initialize SSL context and server socket
        self.context = create_server_ssl_context(ServerConfig.CERT, ServerConfig.KEY)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((ServerConfig.IP, ServerConfig.PORT))
        self.server_socket.listen(ProtocolConfig.MAX_CONNECTIONS)
        
        # Start CA challenge
        self.ca_challenge.initialize()
        self.ca_challenge.run()
        
        self.logger.info(f"Server listening on {ServerConfig.IP}:{ServerConfig.PORT}...")

    def handle_client_request(self, client_socket: socket.socket, messages: List[str]) -> bool:
        """Handle client connection after ICMP challenge completion"""
        try:
            try:
                ssl_socket = self.context.wrap_socket(
                    client_socket, 
                    server_side=True,
                    do_handshake_on_connect=False
                )
                ssl_socket.do_handshake()
            except ssl.SSLError:
                self.logger.info("SSL handshake failed - client likely missing certificate")
                return False

            # Read client request
            request = ssl_socket.recv(1024).decode('utf-8')
            self.logger.info(f"Received request: {request}")

            # Check if the request is "Any body home?"
            if "Any body home?" in request:
                response = (
                    b"HTTP/1.1 200 OK\r\n\r\n"
                    b"Yes, I'm here!\r\n"
                )
                ssl_socket.sendall(response)
                self.logger.info("Responded to 'Any body home?' with 'Yes, I'm here!'")
                return True

            return handle_ssl_request(ssl_socket, messages)

        except Exception as e:
            self.logger.error(f"Error handling client: {e}")
            return False

    def _handle_server_loop(self) -> None:
        """Main server loop handling client connections"""
        encryption_key_printed = False
        start_time = time.time()
            
        while self.running:
            ready, _, _ = select.select([self.server_socket], [], [], 0.1)
            
            # Handle client connections
            if ready:
                client_socket, addr = self.server_socket.accept()
                self.logger.info(f"Client connected from {addr}")
                
                try:
                    messages = self.image_challenge.get_encrypted_messages()
                    if self.handle_client_request(client_socket, messages):
                        self.logger.info("Client request handled successfully")
                    else:
                        self.logger.warning("Failed to handle client request")
                finally:
                    client_socket.close()
            
            # Print encryption key after delay
            if not encryption_key_printed and time.time() - start_time > 5:
                self.image_challenge.print_encryption_key()
                encryption_key_printed = True

    def cleanup(self) -> None:
        """Cleanup resources on server shutdown"""
        if self.server_socket:
            self.server_socket.close()
        self.logger.info("Server stopped")

    

def create_server_ssl_context(cert_content: str, key_content: str) -> ssl.SSLContext:
    """Create an SSL context for the server."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.set_ciphers(SSLConfig.CIPHER_SUITE)
    
    try:
        # Load the certificate and key into the context
        context = _temp_cert_to_context(context, cert_content, key_content)
        
        context.verify_mode = ssl.CERT_REQUIRED 
        context.verify_flags = ssl.VERIFY_DEFAULT
        context.load_verify_locations(cafile=ServerConfig.CA_CERT_PATH)
        
    except Exception as e:
        logging.error(f"Error setting up server SSL context: {e}")
        raise
    
    return context