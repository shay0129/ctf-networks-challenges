"""
Server Utilities Module
Provides SSL, encryption, and file handling utilities for the server.
"""
from typing import Optional, List, Any
import logging
import socket
import atexit
import signal
import queue
import ssl
import os

from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509

from ..protocol import ProtocolConfig, ServerConfig
from ..server_challenges.enigma_challenge import EnigmaChallenge

# Setup utilities
def setup_logging() -> None:
   """Configure logging format and level."""
   logging.basicConfig(
       level=logging.INFO,
       format='%(asctime)s - %(levelname)s - %(message)s'
   )

def setup_signal_handlers(server: Any) -> None:
   """
   Setup graceful shutdown handlers for SIGINT and SIGTERM.
   Args:
       server: CTFServer instance to handle shutdown
   """
   def signal_handler(sig: int, frame: Any) -> None:
       # logging.info("\nShutting down server...")
       server.running = False

   signal.signal(signal.SIGINT, signal_handler)
   signal.signal(signal.SIGTERM, signal_handler)

# File operations
def cleanup(image_path: str) -> None:
   """
   Clean up temporary files.
   Args:
       image_path: Path to file that needs to be removed
   """
   try:
       if os.path.exists(image_path):
           os.remove(image_path)
           # logging.info(f"Cleaned up temporary file: {image_path}")
   except Exception as e:
       logging.error(f"Failed to cleanup temporary file: {e}")

# Certificate operations
def verify_client_cert(cert: bytes) -> bool:
    """
    Verify client certificate is signed by CA and contains required fields.
    """
    if not cert:
        logging.error("No certificate provided")
        return False
    try:
        cert_obj = x509.load_der_x509_certificate(cert, default_backend())
        # logging.info(f"Certificate subject: {cert_obj.subject}")
        # logging.info(f"Certificate issuer: {cert_obj.issuer}")
        # Check Common Name (CN) and Organization (O)
        common_name = None
        organization = None
        for attr in cert_obj.subject:
            if attr.oid == x509.NameOID.COMMON_NAME:
                common_name = attr.value
            if attr.oid == x509.NameOID.ORGANIZATION_NAME:
                organization = attr.value
        if not common_name:
            logging.error("Common Name (CN) not found in certificate subject")
            return False
        if not organization:
            logging.error("Organization (O) not found in certificate subject")
            return False
        if organization != "Sharif University of Technology":
            # logging.error(f"Invalid Organization: {organization}")
            return False
        # logging.info(f"Valid Organization: {organization}")
        # logging.info(f"Valid Common Name: {common_name}")
        # Load and verify against CA public key
        try:
            with open(ServerConfig.CA_CERT_PATH, "rb") as ca_file:
                ca_cert = x509.load_pem_x509_certificate(ca_file.read(), default_backend())
                ca_public_key = ca_cert.public_key()
        except FileNotFoundError:
            logging.error(f"CA certificate not found at {ServerConfig.CA_CERT_PATH}")
            return False
        except Exception as e:
            logging.error(f"Error loading CA certificate: {e}")
            return False
        # Only verify if the CA public key supports it (RSA/ECDSA)
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa, ec
            hash_algo = cert_obj.signature_hash_algorithm
            if hash_algo is None:
                logging.error("Certificate missing signature hash algorithm.")
                return False
            if isinstance(ca_public_key, rsa.RSAPublicKey):
                ca_public_key.verify(
                    cert_obj.signature,
                    cert_obj.tbs_certificate_bytes,
                    asymmetric_padding.PKCS1v15(),
                    hash_algo
                )
            elif isinstance(ca_public_key, ec.EllipticCurvePublicKey):
                ca_public_key.verify(
                    cert_obj.signature,
                    cert_obj.tbs_certificate_bytes,
                    ec.ECDSA(hash_algo)
                )
            else:
                logging.error("CA public key type not supported for verification.")
                return False
            # logging.info("Certificate successfully verified against CA public key")
            return True
        except Exception as e:
            logging.error(f"Certificate verification failed: {e}")
            return False
    except Exception as e:
        logging.error(f"Error processing certificate: {e}")
        return False

# Response formatting
def create_multipart_response(messages: List[str]) -> bytes:
   """
   Create multipart response with encrypted messages.
   Args:
       messages: List of encrypted messages to include in response
   Returns:
       Formatted multipart HTTP response as bytes
   """
   response = [
       b"HTTP/1.1 200 OK",
       b"Content-Type: multipart/mixed; boundary=boundary",
       b"",
       b""
   ]
   response = b"\r\n".join(response)
   for msg in messages:
       response += (
           b"--boundary\r\n"
           b"Content-Type: text/plain\r\n\r\n" +
           msg.encode() +
           b"\r\n"
       )
   response += b"--boundary--\r\n\r\n"
   return response


def setup_server_socket() -> socket.socket:
    """Setup and configure the server socket."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind((ServerConfig.IP, ServerConfig.PORT))
        server_socket.listen(ProtocolConfig.MAX_CONNECTIONS)
        server_socket.setblocking(False)
        # logging.info(f"Server listening on port {ServerConfig.PORT}")
        return server_socket
    except Exception as e:
        logging.error(f"Failed to setup server socket: {e}")
        raise

def handle_ssl_request(
    ssl_socket: ssl.SSLSocket,
    messages: List[str],
    client_message_queue: Optional[queue.Queue[Any]] = None, # Added type argument
    addr: Optional[str] = None
) -> bool:
    """Handle the SSL request from the client, optionally sending messages to a queue."""
    try:
        # --- Certificate Verification Part ---
        client_cert_bytes = ssl_socket.getpeercert(binary_form=True)
        if not client_cert_bytes:
            logging.error(f"No client certificate received from {addr}")
            response = b"HTTP/1.1 403 Forbidden\r\n\r\nClient certificate required\n"
            ssl_socket.sendall(response)
            return False
        if not verify_client_cert(client_cert_bytes):
            response = (
                b"HTTP/1.1 403 Forbidden\r\n\r\n"
                b"Invalid or untrusted client certificate.\n"
            )
            ssl_socket.sendall(response)
            return False
        # --- Initial Interaction Part ---
        # Receive HTTP request from client
        request_data = ssl_socket.recv(4096)
        if not request_data:
            logging.warning(f"No HTTP request received from {addr}")
            return False
        # Parse HTTP request line
        try:
            request_line = request_data.split(b'\r\n', 1)[0]
            method = request_line.split(b' ', 1)[0]
            if method != b'GET':
                logging.warning(f"Received unknown HTTP method '{method.decode(errors='ignore')}'. Expected 'GET'. Closing connection.")
                response = b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid HTTP method. Please use 'GET /resource HTTP/1.1'."
                ssl_socket.sendall(response)
                return False
        except Exception:
            logging.warning(f"Malformed HTTP request from {addr}. Closing connection.")
            response = b"HTTP/1.1 400 Bad Request\r\n\r\nMalformed HTTP request. Please use 'GET /resource HTTP/1.1'."
            ssl_socket.sendall(response)
            return False
        # Send initial prompt
        prompt = b"What is your name?\n"
        ssl_socket.sendall(prompt)
        # Wait for client response with name
        client_name_response = ssl_socket.recv(1024).decode('utf-8').strip()
        # logging.info(f"Received name from {addr}: {client_name_response}")
        # Send name response to GUI queue if available
        if client_message_queue and addr and client_name_response:
            try:
                client_message_queue.put((addr, client_name_response)) # type: ignore
            except Exception as e:
                logging.error(f"Failed to put client name to queue for {addr}: {e}")
        # Send confirmation response
        confirmation_response = (
            b"HTTP/1.1 200 OK\r\n\r\n"
            b"Nice to meet you, " + client_name_response.encode() + b"!\n"
            b"Now, let's play a game!\n"
        )
        ssl_socket.sendall(confirmation_response)
        # --- Enigma Challenge Part ---
        enigma_challenge = EnigmaChallenge()
        if not enigma_challenge.create_challenge_image():
            logging.error(f"Failed to create challenge image for {addr}.")
            response = b"HTTP/1.1 500 Internal Server Error\r\n\r\nFailed to create challenge image."
            ssl_socket.sendall(response)
            return False
        modified_image_path = enigma_challenge.get_image_path()
        if not os.path.exists(modified_image_path):
            logging.error(f"Challenge image not found at {modified_image_path} for {addr}")
            response = b"HTTP/1.1 500 Internal Server Error\r\n\r\nChallenge image not found."
            ssl_socket.sendall(response)
            return False
        # Save pic to public location (consider security implications)
        public_image_path = "C:/Users/Public/Open-Me.png" # Hardcoded path - might need adjustment
        try:
            with open(modified_image_path, 'rb') as src_file, open(public_image_path, 'wb') as dest_file:
                dest_file.write(src_file.read())
            atexit.register(cleanup, public_image_path) # Register cleanup for public file
            # logging.info(f"Challenge image saved to {public_image_path} for {addr}")
        except Exception as e:
            logging.error(f"Failed to save image to public path for {addr}: {e}")
            # Decide if this is fatal
        # Send the image data as a response (This part seems incorrect - sending image directly after 200 OK?)
        # Usually, you'd send headers indicating image content type and length.
        # Let's assume the multipart response handles the image/messages.
        # response_header = b"HTTP/1.1 200 OK\r\n" # This was likely incorrect placement
        # ssl_socket.sendall(response_header) # Remove this line
        # Send encrypted Enigma messages (and potentially image) via multipart
        multipart_response = create_multipart_response(enigma_challenge.get_encrypted_messages())
        ssl_socket.sendall(multipart_response)
        # logging.info(f"Sent Enigma challenge multipart response to {addr}")
        # Cleanup the temporary source image
        atexit.register(cleanup, modified_image_path)
        return True
    except ssl.SSLError as e:
        # Handle SSL errors specifically during the request handling phase
        logging.error(f"SSL error during request handling for {addr}: {e}")
        return False
    except socket.timeout:
        # logging.warning(f"Socket timeout during request handling for {addr}.")
        return False
    except Exception as e:
        logging.error(f"Unexpected error handling request for {addr}: {e}")
        #traceback.print_exc() # Log full traceback for unexpected errors
        return False
    # Note: The 'finally' block for closing the socket is now in CTFServer.handle_collaborator

