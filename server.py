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

from protocol import (
    ServerConfig,ProtocolConfig,
    SSLConfig, ClientConfig
)
from server_utils import (
    extract_ssl_info, 
    hide_key_in_image,
    temp_cert_to_context,
    print_encryption_key, cleanup
)
from base64_picture import get_image_data

__all__ = ['running', 'client_random', 'master_secret']

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Extract the client random and master secret from the SSLKEYLOGFILE
client_random, master_secret = extract_ssl_info(SSLConfig.KEYLOG_CONTENT)

# Keylog strings for the client random and master secret
messages = [
    "1. rteng eqmna jibjl kpvq", # Mission Accomplished.
    "2. xasfh yynve watta epkas mtqot lhlyi rmmpb ifeuv ygsjl gqynv mxois jmjfh pgzle tposh gsoyb hoars lrmks qignd am", # The encryption key has been secured. Intelligence units can now proceed with decrypting IRGC communications.
    "3. xaswp wiqxw tpdih lflyc mykck clqyk sm", # The legacy of the Ritchie Boys lives on.
    f"4. qjxfh nymcq {client_random} rhexp fjjns zp {master_secret}", # Client random: {client_random_keylog} Master secret: {master_secret_keylog}
]


def receive_all(sock, expected_length, timeout=ProtocolConfig.TIMEOUT):
    """
    Receive exact amount of data from socket.
    
    Args:
        sock: Socket object
        expected_length: Number of bytes to receive
        timeout: Timeout in seconds
        
    Returns:
        bytes: Received data
        
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
    """ Verify the client certificate against the CA public key and check CN """
    if not cert:
        print("No certificate provided")
        return False

    try:
        # load the client certificate
        cert_obj = x509.load_der_x509_certificate(cert, default_backend())
        logging.info(f"Certificate subject: {cert_obj.subject}")
        logging.info(f"Certificate issuer: {cert_obj.issuer}")

        # Check Common Name
        for attr in cert_obj.subject:
            if attr.oid == x509.NameOID.COMMON_NAME:
                #if attr.value != ClientConfig.HOSTNAME_REQUESTED:
                if attr.value != ClientConfig.HOSTNAME:
                    logging.error(f"Invalid Common Name: {attr.value}")
                    return False

        # load the CA public key from ca.crt
        with open("ca.crt", "rb") as ca_file:
            ca_cert = x509.load_pem_x509_certificate(ca_file.read(), default_backend())
            ca_public_key = ca_cert.public_key()
        
        # Verify the signature on the client certificate
        ca_public_key.verify(
            cert_obj.signature,
            cert_obj.tbs_certificate_bytes,
            asymmetric_padding.PKCS1v15(),
            cert_obj.signature_hash_algorithm,
        )
        
        print("Certificate successfully verified against CA public key")
        return True
    except Exception as e:
        logging.error(f"Verification failed: {e}")
        return False

def handle_client_request(ssl_socket):
    try:
        # Get the binary form of the client certificate
        cert = ssl_socket.getpeercert(binary_form=True)
        if not cert:
            response = b"HTTP/1.1 400 Bad Request\r\n\r\n"
            response += b"No client certificate provided\r\n"
            ssl_socket.sendall(response)
            return False
        
        # Verify the client certificate first
        if not verify_client_cert(cert):
            response = b"HTTP/1.1 403 Forbidden\r\n\r\n"
            response += b"=== Certificate Authority Error ===\n"
            response += b"The certificate must be signed by a trusted CA\n"  
            response += b"Found ca.crt - this CA must sign your certificate\n"
            response += b"Invalid Common Name in certificate - should be: " + ClientConfig.HOSTNAME.encode() + b"\n"
            response += b"Hint: OpenSSL is your friend...\n"
            response += b"=================================\n"
            ssl_socket.sendall(response)
            ssl_socket.close()  # Close the connection
            return False

        # Encrypt the key in the image
        enigma_add = "{reflector} UKW B {ROTOR_POSITION_RING} VI A A I Q A III L A {PLUGBOARD} bq cr di ej kw mt os px uz gh"
        modified_image_data = hide_key_in_image(get_image_data(), enigma_add)
        
        # Save the modified image to a file
        modified_image_path = os.path.join(os.path.expanduser("~"), "Open-Me.png")
        with open(modified_image_path, 'wb') as f:
            f.write(modified_image_data)
        atexit.register(cleanup, modified_image_path)

        # Build the HTTP response
        response = b"HTTP/1.1 200 OK\r\n"
        response += b"Content-Type: multipart/mixed; boundary=boundary\r\n\r\n"
        
        # Add the encrypted strings to the response
        for msg in messages:
            response += b"--boundary\r\n"
            response += b"Content-Type: text/plain\r\n\r\n"
            response += msg.encode()
            response += b"\r\n"
        
        # Finish the response
        response += b"--boundary--\r\n\r\n"
        
        print(f"Sending response of {len(response)} bytes")
        ssl_socket.sendall(response)
        return True

    except Exception as e:
        print(f"Error handling client: {e}")
        ssl_socket.sendall(b"HTTP/1.1 500 Internal Server Error\r\n\r\nAn error occurred")
        return False

def create_server_ssl_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.set_ciphers('AES128-SHA256')
    context = temp_cert_to_context(context, ServerConfig.CERT, ServerConfig.KEY)
        
    context.verify_mode = ssl.CERT_REQUIRED
    context.verify_flags = ssl.VERIFY_DEFAULT

    # Load the CA certificate, and use public key to verify client certificates
    context.load_verify_locations(cafile="ca.crt")
    return context

    
# Global flag to indicate if the server should continue running
running = True

def main():
    global running
    
    context = create_server_ssl_context()

    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind((ServerConfig.IP, ServerConfig.PORT))
    except Exception as e:
        logging.error(f"Failed to bind to port {ServerConfig.PORT}: {e}")
        return
    server_socket.listen(ProtocolConfig.MAX_CONNECTIONS)
    server_socket.setblocking(False)  # Set socket to non-blocking mode

    print(f"Server is up and running, waiting for a client on port {ServerConfig.PORT}...")

    start_time = time.time()
    key_printed = False

    try:
        while running:
            # Use select to wait for a connection with a short timeout
            ready, _, _ = select.select([server_socket], [], [], 0.1)
            
            if ready:
                client_socket, client_address = server_socket.accept()
                logging.info(f"Client connected from {client_address}")
                ssl_socket = None  # Initialize ssl_socket to None

                try:
                    ssl_socket = context.wrap_socket(client_socket, 
                                                    server_side=True,
                                                    do_handshake_on_connect=False)
                    ssl_socket.do_handshake()
                    if handle_client_request(ssl_socket):
                        print("Client request handled successfully")
                    else:
                        print("Failed to handle client request")
                except ssl.SSLError as e:
                    print()
                except Exception as e:
                    print(f"Unexpected error: {e}")
                finally:
                    if ssl_socket:
                        ssl_socket.close()
                    if client_socket:
                        client_socket.close()
            else:
                # No connection within the timeout period
                if not key_printed and time.time() - start_time > 5:
                    print_encryption_key()
                    key_printed = True
                print("Waiting for a new connection...", end='\r')
                


    finally:
        print("\nClosing server socket...")
        server_socket.close()
        print("Server has been shut down.")

if __name__ == '__main__':
    main()