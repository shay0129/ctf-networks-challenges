import socket
import ssl
import protocol

def create_client_ssl_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.set_ciphers('AES128-SHA256')

    # Load the client certificate and private key
    try:
        context.load_cert_chain(certfile="client.crt", keyfile="client.key")
        print("Client certificate and key loaded successfully")
    except Exception as e:
        print(f"Error loading client certificate or key: {e}")
    
    # Disable server cert verification for self-signed certs
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Disable server cert verification

    return context

def client():
    # Create SSL context
    context = create_client_ssl_context()

    print(f"Connecting to {protocol.SERVER_IP}:{protocol.SERVER_PORT}")

    try:
        # Create a raw TCP connection
        with socket.create_connection((protocol.SERVER_IP, protocol.SERVER_PORT)) as sock:
            # Wrap it in SSL
            with context.wrap_socket(sock, do_handshake_on_connect=False) as secure_sock:
                
                # Explicitly perform the handshake
                try:
                    secure_sock.do_handshake()
                    print(f"Handshake successful with {secure_sock.getpeername()}")
                except ssl.SSLError as e:
                    print(f"Handshake failed: {e}")
                    return  # Exit if the handshake fails

                print(f"Using cipher: {secure_sock.cipher()}")
                print(f"SSL version: {secure_sock.version()}")

                # Debug: Check if the client certificate was sent
                if secure_sock.getpeercert(binary_form=True):
                    print("Client certificate was sent to the server")
                else:
                    print("Warning: Client certificate was not sent to the server")

                # Send a GET request to the server
                request = f"GET /resource HTTP/1.1\r\nHost: {protocol.SERVER_HOSTNAME}\r\n\r\n"
                secure_sock.sendall(request.encode())

                # Receive and print the response
                response = b""
                while True:
                    chunk = secure_sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    print(f"Received chunk of {len(chunk)} bytes")
                
                # Output the full response
                print(f"Full response:\n{response.decode('utf-8', errors='ignore')}")

    except ssl.SSLError as e:
        print(f"SSL Error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print("Connection closed")

if __name__ == "__main__":
    client()
