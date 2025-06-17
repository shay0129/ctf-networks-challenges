"""
Server Utilities Module
Provides SSL, encryption, and file handling utilities for the server.
"""
from typing import List, Any
import logging
import socket
import signal
import os

from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509

from ..protocol import ProtocolConfig, ServerConfig

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
            with open('ca.crt', "rb") as ca_file:
                ca_cert = x509.load_pem_x509_certificate(ca_file.read(), default_backend())
                ca_public_key = ca_cert.public_key()
        except FileNotFoundError:
            logging.error(f"CA certificate not found at {'ca.crt'}")
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

