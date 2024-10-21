# server.py
import socket
import ssl
import time
import protocol
import select
import signal
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os
from server_utils import *

client_random, master_secret = extract_ssl_info(SSLKEYLOG_CONTENT)

messages = [
    "rteng eqmna jibjl kpvq", # Mission Accomplished.
    "xasfh yynve watta epkas mtqot lhlyi rmmpb ifeuv ygsjl gqynv mxois jmjfh pgzle tposh gsoyb hoars lrmks qignd am", # The encryption key has been secured. Intelligence units can now proceed with decrypting IRGC communications.
    "xaswp wiqxw tpdih lflyc mykck clqyk sm", # The legacy of the Ritchie Boys lives on.
    f"qjxfh nymcq {client_random} rhexp fjjns zp {master_secret}", # Client random: {client_random_keylog} Master secret: {master_secret_keylog}
]

def receive_all(sock, expected_length):
    data = b""
    while len(data) < expected_length:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("Socket connection broken")
        data += chunk
    return data


def verify_client_cert(cert):
    if not cert:
        print("No certificate provided")
        return False

    try:
        cert_obj = x509.load_der_x509_certificate(cert, default_backend())
        subject = cert_obj.subject
        print(f"Certificate subject: {subject}")
        
        country = subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)
        print(f"Country: {country[0].value if country else 'None'}")
        
        return True
    except Exception as e:
        print(f"Verification error: {e}")
        return False


def handle_client_request(ssl_socket):
    try:
        # Receive HTTP GET request first
        request = ssl_socket.recv(1024).decode()
        if not request.startswith("GET /resource"):
            ssl_socket.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid request")
            return False

        # Get the binary form of the client certificate
        cert = ssl_socket.getpeercert(binary_form=True)
        if not cert:
            ssl_socket.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\nNo client certificate provided")
            print("No client certificate received")
            return False
        
        if not verify_client_cert(cert):
            ssl_socket.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\nInvalid client certificate")
            return False

        # Encrypt the key in the image
        enigma_add = "{reflector} UKW B {ROTOR POSITION RING} VI A A I Q A III L A {PLUGBOARD} bq cr di ej kw mt os px uz gh"
        modified_image_data = hide_key_in_image(get_image_data(), enigma_add)
        
        # Save the modified image to a file
        modified_image_path = os.path.join(os.path.expanduser("~"), "Open-Me.png")
        with open(modified_image_path, 'wb') as f:
            f.write(modified_image_data)
        print(f"Look at: {modified_image_path}")

        response = b"HTTP/1.1 200 OK\r\n"
        response += b"Content-Type: multipart/mixed; boundary=boundary\r\n\r\n"
        
        response += b"--boundary\r\n"
        response += b"Content-Type: image/png\r\n"
        response += f"Content-Disposition: attachment; filename=\"Open-Me.png\"\r\n\r\n".encode()
        #response += modified_image_data + b"\r\n"
        
        ssl_socket.sendall(response)

        for msg in messages:
            part = b""
            part += msg.encode() + b"\r\n"
            ssl_socket.sendall(part)
            #print(msg)
            # Instead of sleeping, we could implement a non-blocking delay here
            # For now, we'll remove the sleep to avoid potential timeouts
            time.sleep(5)

        ssl_socket.sendall(b"--boundary--\r\n")
        return True

    except ssl.SSLError as e:
        print(f"SSL Error handling client: {e}")
        ssl_socket.sendall(b"HTTP/1.1 500 Internal Server Error\r\n\r\nSSL Error occurred")
    except Exception as e:
        print(f"Error handling client: {e}")
        ssl_socket.sendall(b"HTTP/1.1 500 Internal Server Error\r\n\r\nAn error occurred")
    return False

def create_server_ssl_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.set_ciphers('AES128-SHA256')
    context = temp_cert_to_context(context, SERVER_CRT, SERVER_KEY)
    
    context.verify_mode = ssl.CERT_REQUIRED  # שינוי מ-CERT_OPTIONAL
    context.verify_flags = ssl.VERIFY_DEFAULT
    context.load_verify_locations(cafile="ca.crt") # load certificate authority
    return context

    
# Global flag to indicate if the server should continue running
running = True

def main():
    global running
    
    context = create_server_ssl_context()

    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((protocol.SERVER_IP, protocol.SERVER_PORT))
    server_socket.listen(5)
    server_socket.setblocking(False)  # Set socket to non-blocking mode

    print(f"Server is up and running, waiting for a client on port {protocol.SERVER_PORT}...")

    start_time = time.time()
    key_printed = False

    try:
        while running:
            # Use select to wait for a connection with a short timeout
            ready, _, _ = select.select([server_socket], [], [], 0.1)
            
            if ready:
                client_socket, client_address = server_socket.accept()
                print(f"Client connected from {client_address}")
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
                    if ssl_socket:  # Check if ssl_socket was created
                        ssl_socket.close()
                    print("Connection closed")
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