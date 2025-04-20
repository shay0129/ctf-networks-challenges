"""
Server Implementation Module
Implements sequential CTF challenges starting with ICMP

"""
from typing import List, Optional
import traceback
import threading
import logging
import socket
import select
import time
import ssl
import queue

from .protocol import ServerConfig, ProtocolConfig, SSLConfig
from .utils.server import handle_ssl_request, _temp_cert_to_context
from .server_challenges.icmp_challenge import start_icmp_server
from .server_challenges.ca_challenge import CAChallenge
from .server_challenges.enigma_challenge import EnigmaChallenge

class CTFServer:
    """Main CTF server managing all challenges sequentially"""
    # Accept queues in constructor
    def __init__(self, client_update_queue=None, client_message_queue=None):
        self.running = True
        self.icmp_completed = False
        self.ca_challenge = CAChallenge()
        self.image_challenge = EnigmaChallenge()
        self.server_socket: Optional[socket.socket] = None
        self.context: Optional[ssl.SSLContext] = None
        # self.client_random = None # Seems unused
        # self.master_secret = None # Seems unused
        self.logger = logging.getLogger('server')
        self.collaborator_sockets: List[ssl.SSLSocket] = [] # Store sockets if needed elsewhere
        self.collaborator_threads: List[threading.Thread] = []
        # Store the queues
        self.client_update_queue = client_update_queue
        self.client_message_queue = client_message_queue

    def run(self) -> None:
        """Runs the ICMP challenge first, then initializes and runs the main TLS server loop if ICMP succeeds."""
        try:
            # Run ICMP challenge first
            self.logger.info("Starting ICMP Challenge...")
            # Call the imported function directly, not as a method of self
            icmp_success = start_icmp_server() # CORRECTED CALL

            if not icmp_success:
                self.logger.error("ICMP Challenge failed or was not completed. Stopping server.")
                return # Exit the run method if ICMP failed

            # If ICMP succeeded, proceed with TLS server
            self.logger.info("ICMP Challenge completed successfully. Starting TLS Collaborator Server...")
            self.initialize_collaborator_server()
            self._handle_collaborator_connections()

        except Exception as e:
            self.logger.error(f"Server run failed: {e}")
            #traceback.print_exc()
        finally:
            self.cleanup() # Ensure cleanup is called when the loop exits or run finishes

    def initialize_collaborator_server(self) -> None:
        """Initialize server to listen for collaborator connections."""
        self.logger.info("Initializing server for collaborator connections...")
        self.context = create_server_ssl_context(ServerConfig.CERT, ServerConfig.KEY)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((ServerConfig.IP, ServerConfig.PORT))
        self.server_socket.listen(ProtocolConfig.MAX_CONNECTIONS)
        self.server_socket.setblocking(False)
        self.logger.info(f"Listening for collaborator connections on {ServerConfig.IP}:{ServerConfig.PORT}")

    def handle_collaborator(self, ssl_socket: ssl.SSLSocket, addr: tuple) -> None:
        """Handle communication with a connected collaborator using handle_ssl_request."""
        addr_str = str(addr) # Use string representation for queue/listbox
        try:
            self.logger.info(f"Handling collaborator connection from {addr_str}")
            # Pass the message queue and address to handle_ssl_request
            if handle_ssl_request(ssl_socket, [], client_message_queue=self.client_message_queue, addr=addr_str):
                self.logger.info(f"Collaborator {addr_str} request handled successfully by handle_ssl_request.")
            else:
                self.logger.warning(f"handle_ssl_request failed for collaborator {addr_str}.")

        except ssl.SSLError as e:
             self.logger.error(f"SSL error during communication with {addr_str}: {e}")
        except socket.timeout:
             self.logger.warning(f"Socket timeout during communication with {addr_str}.")
        except Exception as e:
            self.logger.error(f"Error handling collaborator {addr_str}: {e}")
            #traceback.print_exc()
        finally:
            # Cleanup: Close the socket and notify GUI of disconnection
            try:
                ssl_socket.close()
                # Remove from internal list if necessary
                if ssl_socket in self.collaborator_sockets:
                    self.collaborator_sockets.remove(ssl_socket)
                # Notify GUI about disconnection
                if self.client_update_queue:
                    self.client_update_queue.put(('disconnect', addr_str))
            except Exception as e:
                self.logger.error(f"Error closing/removing socket for {addr_str}: {e}")
            self.logger.info(f"Connection with collaborator {addr_str} closed.")

    def _handle_collaborator_connections(self) -> None:
        """Accept and handle incoming collaborator connections."""
        encryption_key_printed = False
        start_time = time.time()

        while self.running:
            ready, _, _ = select.select([self.server_socket], [], [], 0.1)

            if ready:
                client_socket, addr = self.server_socket.accept()
                addr_str = str(addr) # Use string representation
                self.logger.info(f"Server: Collaborator connected from {addr_str}")
                try:
                    ssl_socket = self.context.wrap_socket(
                        client_socket,
                        server_side=True,
                        do_handshake_on_connect=True
                    )
                    self.collaborator_sockets.append(ssl_socket) # Keep track if needed

                    # Notify GUI about connection *before* starting thread
                    if self.client_update_queue:
                        self.client_update_queue.put(('connect', addr_str))

                    # Start handler thread
                    thread = threading.Thread(target=self.handle_collaborator, args=(ssl_socket, addr))
                    self.collaborator_threads.append(thread)
                    thread.daemon = True # Ensure threads exit when main program exits
                    thread.start()

                except ssl.SSLError as e:
                    self.logger.error(f"SSL Handshake with {addr_str} failed: {e}")
                    client_socket.close()
                    # Optionally notify GUI of failed connection attempt if needed
                except Exception as e:
                    self.logger.error(f"Error wrapping socket for {addr_str}: {e}")
                    client_socket.close()
                    # Optionally notify GUI of failed connection attempt if needed

            # Print encryption key after delay (only once)
            if not encryption_key_printed and time.time() - start_time > 5:
                self.image_challenge.print_encryption_key()
                encryption_key_printed = True

            # Basic cleanup of finished threads (optional, but good practice)
            self.collaborator_threads = [t for t in self.collaborator_threads if t.is_alive()]

    def cleanup(self) -> None:
        """Cleanup resources on server shutdown"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        for sock in self.collaborator_sockets:
            try:
                sock.close()
            except Exception:
                pass
        for thread in self.collaborator_threads:
            try:
                thread.join(timeout=1)
            except Exception:
                pass
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