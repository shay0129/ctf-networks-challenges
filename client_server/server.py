"""
Server Implementation Module
Implements SSL server with client certificate verification and message handling.
"""
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509

import logging
import atexit
import socket
import select
import time
import ssl
import os

from protocol import ServerConfig, ProtocolConfig, ClientConfig
from server_utils import (
    extract_ssl_info, 
    hide_key_in_image,
    temp_cert_to_context,
    print_encryption_key, 
    cleanup
)
from base64_picture import get_image_data

__all__ = ['running', 'client_random', 'master_secret']

# Initialize session data
client_random, master_secret = extract_ssl_info()
running = True

# Encrypted messages
messages = [
    "1. rteng eqmna jibjl kpvq",  # Mission Accomplished.
    "2. xasfh yynve watta epkas mtqot lhlyi rmmpb ifeuv ygsjl gqynv mxois jmjfh pgzle tposh gsoyb hoars lrmks qignd am",  # Key secured
    "3. xaswp wiqxw tpdih lflyc mykck clqyk sm",  # Legacy lives on
    f"4. qjxfh nymcq {client_random} rhexp fjjns zp {master_secret}",  # Session keys
]

def receive_all(sock: socket.socket, expected_length: int, timeout: int = ProtocolConfig.TIMEOUT) -> bytes:
    """
    Receive exact amount of data from socket.

    Args:
        sock: Socket object to receive from
        expected_length: Number of bytes to receive
        timeout: Operation timeout in seconds

    Returns:
        Received data

    Raises:
        TimeoutError: If operation times out
        RuntimeError: If connection breaks
    """
    sock.settimeout(timeout)
    data = b""
    
    try:
        while len(data) < expected_length:
            chunk = sock.recv(ProtocolConfig.SOCKET_BUFFER_SIZE)
            if not chunk:
                raise RuntimeError("Socket connection broken")
            data += chunk
        return data
    except socket.timeout:
        raise TimeoutError("Receive operation timed out")

def verify_client_cert(cert: bytes) -> bool:
    """
    Verify client certificate against CA and check Common Name.

    Args:
        cert: Client certificate in DER format

    Returns:
        True if certificate is valid, False otherwise
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
                if attr.value != ClientConfig.HOSTNAME_REQUESTED:
                    logging.error(f"Invalid Common Name: {attr.value}")
                    return False

        # Load and verify against CA
        with open("ca.crt", "rb") as ca_file:
            ca_cert = x509.load_pem_x509_certificate(ca_file.read(), default_backend())
            ca_public_key = ca_cert.public_key()
        
        ca_public_key.verify(
            cert_obj.signature,
            cert_obj.tbs_certificate_bytes,
            asymmetric_padding.PKCS1v15(),
            cert_obj.signature_hash_algorithm,
        )
        
        logging.info("Certificate successfully verified against CA public key")
        return True
    except Exception as e:
        logging.error(f"Verification failed: {e}")
        return False

def handle_client_request(ssl_socket: ssl.SSLSocket) -> bool:
    """
    Handle incoming client connection and certificate verification.

    Args:
        ssl_socket: Established SSL socket

    Returns:
        True if request handled successfully, False otherwise
    """
    try:
        # Verify client certificate
        cert = ssl_socket.getpeercert(binary_form=True)
        if not cert:
            response = (
                b"HTTP/1.1 400 Bad Request\r\n\r\n"
                b"No client certificate provided\r\n"
            )
            ssl_socket.sendall(response)
            return False
        
        if not verify_client_cert(cert):
            response = (
                b"HTTP/1.1 403 Forbidden\r\n\r\n"
                b"=== Certificate Authority Error ===\n"
                b"The certificate must be signed by a trusted CA\n"
                b"Found ca.crt - this CA must sign your certificate\n"
                b"Invalid Common Name in certificate - should be: " + 
                ClientConfig.HOSTNAME.encode() + b"\n"
                b"Hint: OpenSSL is your friend...\n"
                b"=================================\n"
            )
            ssl_socket.sendall(response)
            return False

        # Prepare encrypted response
        enigma_add = "{reflector} UKW B {ROTOR_POSITION_RING} VI A A I Q A III L A {PLUGBOARD} bq cr di ej kw mt os px uz gh"
        modified_image_data = hide_key_in_image(get_image_data(), enigma_add)
        
        # Save modified image
        modified_image_path = os.path.join(os.path.expanduser("~"), "Open-Me.png")
        with open(modified_image_path, 'wb') as f:
            f.write(modified_image_data)
        atexit.register(cleanup, modified_image_path)

        # Send multipart response
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
        
        logging.info(f"Sending response of {len(response)} bytes")
        ssl_socket.sendall(response)
        return True

    except Exception as e:
        logging.error(f"Error handling client: {e}")
        ssl_socket.sendall(b"HTTP/1.1 500 Internal Server Error\r\n\r\nAn error occurred")
        return False

def create_server_ssl_context() -> ssl.SSLContext:
    """
    Create and configure SSL context for the server.

    Returns:
        Configured SSL context
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.set_ciphers('AES128-SHA256')
    context = temp_cert_to_context(context, ServerConfig.CERT, ServerConfig.KEY)
    
    context.verify_mode = ssl.CERT_REQUIRED
    context.verify_flags = ssl.VERIFY_DEFAULT
    context.load_verify_locations(cafile="ca.crt")
    
    return context

def main() -> None:
    """Main server function that handles incoming connections."""
    context = create_server_ssl_context()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind((ServerConfig.IP, ServerConfig.PORT))
    except Exception as e:
        logging.error(f"Failed to bind to port {ServerConfig.PORT}: {e}")
        return

    server_socket.listen(ProtocolConfig.MAX_CONNECTIONS)
    server_socket.setblocking(False)
    
    logging.info(f"Server listening on port {ServerConfig.PORT}")

    start_time = time.time()
    key_printed = False

    try:
        while running:
            ready, _, _ = select.select([server_socket], [], [], 0.1)
            
            if ready:
                client_socket, addr = server_socket.accept()
                logging.info(f"Client connected from {addr}")

                try:
                    ssl_socket = context.wrap_socket(
                        client_socket, 
                        server_side=True,
                        do_handshake_on_connect=False
                    )
                    ssl_socket.do_handshake()
                    
                    if handle_client_request(ssl_socket):
                        logging.info("Client request handled successfully")
                    else:
                        logging.warning("Failed to handle client request")
                        
                except ssl.SSLError as e:
                    logging.error(f"SSL Error: {e}")
                except Exception as e:
                    logging.error(f"Unexpected error: {e}")
                finally:
                    if 'ssl_socket' in locals():
                        ssl_socket.close()
                    client_socket.close()
            else:
                if not key_printed and time.time() - start_time > 5:
                    print_encryption_key()
                    key_printed = True

    except KeyboardInterrupt:
        logging.info("Server shutdown requested")
    finally:
        logging.info("Closing server socket")
        server_socket.close()
        logging.info("Server stopped")

if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    main()