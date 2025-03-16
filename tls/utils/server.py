"""
Server Utilities Module
Provides SSL, encryption, and file handling utilities for the server.
"""
from typing import Optional, Union, List
import logging
import signal
import os
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from tls.protocol import ProtocolConfig, ClientConfig, ServerConfig
from tls.server_challenges.image_challenge import ImageChallenge
import ssl
import socket
import tempfile
import atexit

# Setup utilities
def setup_logging() -> None:
   """Configure logging format and level."""
   logging.basicConfig(
       level=logging.INFO,
       format='%(asctime)s - %(levelname)s - %(message)s'
   )

def setup_signal_handlers(server) -> None:
   """
   Setup graceful shutdown handlers for SIGINT and SIGTERM.
   
   Args:
       server: CTFServer instance to handle shutdown
   """
   def signal_handler(sig: int, frame) -> None:
       logging.info("\nShutting down server...")
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
           logging.info(f"Cleaned up temporary file: {image_path}")
   except Exception as e:
       logging.error(f"Failed to cleanup temporary file: {e}")

# Certificate operations
def verify_client_cert(cert: bytes) -> bool:
   """
   Verify client certificate against CA and check Common Name.
   """
   if not cert:
       logging.error("No certificate provided")
       return False

   try:
       cert_obj = x509.load_der_x509_certificate(cert, default_backend())
       logging.info(f"Certificate subject: {cert_obj.subject}")
       logging.info(f"Certificate issuer: {cert_obj.issuer}")

       # Verify Common Name
       for attr in cert_obj.subject:
           if attr.oid == x509.NameOID.COMMON_NAME:
               if attr.value != ClientConfig.HOSTNAME:
                   logging.error(f"Invalid Common Name: {attr.value}")
                   return False

       # Load and verify against CA
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
       
       try:
           ca_public_key.verify(
               cert_obj.signature,
               cert_obj.tbs_certificate_bytes,
               asymmetric_padding.PKCS1v15(),
               cert_obj.signature_hash_algorithm,
           )
           logging.info("Certificate successfully verified against CA public key")
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

def _temp_cert_to_context(context: ssl.SSLContext, cert_content: Union[str, bytes], key_content: Optional[Union[str, bytes]] = None) -> ssl.SSLContext:
    """Create temporary files to store the certificate and key, and load them into the SSL context."""
    cert_path = key_path = None
    try:
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as temp_cert:
            if isinstance(cert_content, str):
                temp_cert.write(cert_content.encode())
            else:
                temp_cert.write(cert_content)
            cert_path = temp_cert.name
            
        if key_content:
            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as temp_key:
                if isinstance(key_content, str):
                    temp_key.write(key_content.encode())
                else:
                    temp_key.write(key_content)
                key_path = temp_key.name
        
        # Load the certificate and key into the context
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        return context
    except Exception as e:
        logging.error(f"Error processing certificates: {e}")
        raise
    finally:
        # Verifying that the files were created and deleting them
        if cert_path and os.path.exists(cert_path):
            os.unlink(cert_path)
        if key_path and os.path.exists(key_path):
            os.unlink(key_path)



def setup_server_socket() -> socket.socket:
    """Setup and configure the server socket."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind((ServerConfig.IP, ServerConfig.PORT))
        server_socket.listen(ProtocolConfig.MAX_CONNECTIONS)
        server_socket.setblocking(False)
        logging.info(f"Server listening on port {ServerConfig.PORT}")
        return server_socket
    except Exception as e:
        logging.error(f"Failed to setup server socket: {e}")
        raise

def handle_ssl_request(ssl_socket: ssl.SSLSocket, messages: List[str]) -> bool:
    """Handle the SSL request from the client"""
    try:
        cert = ssl_socket.getpeercert(binary_form=True)
        if not verify_client_cert(cert):
            response = (
                b"HTTP/1.1 403 Forbidden\r\n\r\n"
                b"=== Certificate Authority Error ===\n"
                b"The certificate must be signed by a trusted CA\n"
                b"Invalid Common Name in certificate - should be: " + 
                ClientConfig.HOSTNAME_REQUESTED.encode() + b"\n"  # שימוש ב-HOSTNAME_REQUESTED
                b"=================================\n"
            )
            ssl_socket.sendall(response)
            return False

        # Create encrypted config to hide in hex view
        enigma_add = "{reflector} UKW B {ROTOR_POSITION_RING} VI A A I Q A III L A {PLUGBOARD} bq cr di ej kw mt os px uz gh"
        modified_image_data = ImageChallenge.hide_key_in_image(ImageChallenge.get_image_data(), enigma_add)
        
        # Save pic
        modified_image_path = "C:/Users/Public/Open-Me.png"
        with open(modified_image_path, 'wb') as f:
            f.write(modified_image_data)
        atexit.register(cleanup, modified_image_path)

        # Send response
        response = create_multipart_response(messages)
        ssl_socket.sendall(response)
        return True

    except Exception as e:
        logging.error(f"Error in SSL request: {e}")
        return False
        