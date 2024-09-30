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
from server_utils import hide_key_in_image
messages = [
    "rteng eqmna jibjl kpvq", # Mission Accomplished.
    "xasfh yynve watta epkas mtqot lhlyi rmmpb ifeuv ygsjl gqynv mxois jmjfh pgzle tposh gsoyb hoars lrmks qignd am", # The encryption key has been secured. Intelligence units can now proceed with decrypting IRGC communications.
    "xaswp wiqxw tpdih lflyc mykck clqyk sm" # The legacy of the Ritchie Boys lives on.
]

def print_encryption_key():
    print(f"Use the key: {protocol.ENCRYPTION_KEY}")

def receive_all(sock, expected_length):
    data = b""
    while len(data) < expected_length:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("Socket connection broken")
        data += chunk
    return data



def verify_client_cert(cert, csr_data):
    if not cert:
        print("No client certificate provided")
        return False

    try:
        # Parse the certificate
        cert_obj = x509.load_der_x509_certificate(cert, default_backend())
        
        # Check certificate fields
        subject = cert_obj.subject
        issuer = cert_obj.issuer
        
        # Verify that it's a self-signed certificate
        if subject != issuer:
            print("Certificate is not self-signed")
            return False
        
        # Check specific fields
        country = subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)
        common_name = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        
        if not country or country[0].value != "IL":
            print("Invalid country in certificate")
            return False
        
        if not common_name or common_name[0].value != "Pasdaran.local":
            print("Invalid common name in certificate")
            return False
        
        # Parse the CSR
        csr_obj = x509.load_pem_x509_csr(csr_data.encode(), default_backend())
        
        # Compare CSR public key with certificate public key
        if cert_obj.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ) != csr_obj.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ):
            print("CSR public key does not match certificate public key")
            return False
        
        print("Client certificate and CSR verified successfully")
        return True
    
    except Exception as e:
        print(f"Error verifying certificate: {e}")
        return False

def handle_client_request(ssl_socket):
    try:
        # Receive HTTP GET request first
        request = ssl_socket.recv(1024).decode()
        if not request.startswith("GET /resource"):
            print("Invalid request")
            return False

        # Check for client certificate
        cert = ssl_socket.getpeercert(binary_form=True)
        if not cert:
            print("No client certificate provided")
            # Don't send any response for clients without certificates
            return False
        
        print("Client certificate received.")
        
        # Request CSR file
        response = "HTTP/1.1 100 Continue\r\nContent-Type: text/plain\r\n\r\n"
        response += "Please provide your CSR file for verification."
        ssl_socket.sendall(response.encode())
        print("Requested CSR file from client")
        
        # Wait for CSR file
        csr_data = b""
        while True:
            chunk = ssl_socket.recv(4096)
            if not chunk:
                break
            csr_data += chunk
            if b"-----END CERTIFICATE REQUEST-----" in csr_data:
                break
        
        csr_data = csr_data.decode()
        print(f"Received CSR data (length: {len(csr_data)} bytes)")
        
        if verify_client_cert(cert, csr_data):
            print("Valid GET request received. Proceeding with the response.")
            original_image_path = "ctf_challenge.png"
            modified_image_path = os.path.join(os.path.expanduser("~"), "ctf_challenge_modified.png")

            enigma_add = 'reflector:UKW_B.{ROTOR,POSITION,RING}:VI,1A,1A/I,17Q,1A/III,12L,1A.PLUGBOARD:bq_cr_di_ej_kw_mt_os_px_uz_gh'
            modified_image_data = hide_key_in_image(original_image_path, enigma_add)
                        
            with open(modified_image_path, 'wb') as f:
                f.write(modified_image_data)
            print(f"Look at: {modified_image_path}")

            response = b"HTTP/1.1 200 OK\r\n"
            response += b"Content-Type: multipart/mixed; boundary=boundary\r\n\r\n"
            
            response += b"--boundary\r\n"
            response += b"Content-Type: image/png\r\n"
            response += f"Content-Disposition: attachment; filename=\"ctf_challenge_modified.png\"\r\n\r\n".encode()
            response += modified_image_data + b"\r\n"
            
            for msg in messages:
                response += b"--boundary\r\n"
                response += b"Content-Type: text/plain\r\n\r\n"
                response += msg.encode() + b"\r\n"
                print(msg)
                time.sleep(5)  # Wait 5 seconds between messages
            
            response += b"--boundary--\r\n"
            
            ssl_socket.sendall(response)
            return True
        else:
            print("Client certificate verification failed")
            return False

    except Exception as e:
        print(f"Error handling client: {e}")
        return False
    
    
# Global flag to indicate if the server should continue running
running = True

def signal_handler(signum, frame):
    global running
    running = False
    print("\nReceived interrupt signal. Shutting down the server...")

def main():
    global running
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.set_ciphers('AES128-SHA256')
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    context.verify_mode = ssl.CERT_OPTIONAL  # Allow optional client cert
    context.check_hostname = False
    context.verify_flags = ssl.VERIFY_DEFAULT | ssl.VERIFY_X509_TRUSTED_FIRST
    context.load_verify_locations(cafile="client.crt")  # Trust the client's self-signed cert

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((protocol.SERVER_IP, protocol.SERVER_PORT))
    server_socket.listen(5)
    server_socket.setblocking(False)  # Set socket to non-blocking mode

    print(f"Server is up and running, waiting for a client on port {protocol.SERVER_PORT}...")
    print("Press Ctrl+C to stop the server.")

    start_time = time.time()
    key_printed = False

    # Set up the signal handler
    signal.signal(signal.SIGINT, signal_handler)

    try:
        while running:
            # Use select to wait for a connection with a short timeout
            ready, _, _ = select.select([server_socket], [], [], 0.1)
            
            if ready:
                client_socket, client_address = server_socket.accept()
                print(f"Client connected from {client_address}")

                try:
                    ssl_socket = context.wrap_socket(client_socket, server_side=True)
                    print("SSL handshake successful")
                    print(f"Using cipher: {ssl_socket.cipher()}")
                    print(f"SSL version: {ssl_socket.version()}")
                    
                    if handle_client_request(ssl_socket):
                        print("Client request handled successfully")
                    else:
                        print("Failed to handle client request")
                except ssl.SSLError as e:
                    print(f"SSL Error: {e}")
                except Exception as e:
                    print(f"Unexpected error: {e}")
                finally:
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