from protocol import ServerConfig, ProtocolConfig
import socket
import ssl

def create_client_ssl_context() -> ssl.SSLContext:
    """Create an SSL context for the client."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.set_ciphers('AES128-SHA256')
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    # Load the client certificate and private key
    try:
        context.load_cert_chain(certfile="client.crt", keyfile="client.key")
        print("Client certificate and key loaded successfully")
    except Exception as e:
        print(f"Error loading client certificate or key: {e}")
    
    return context

def client():
    context = create_client_ssl_context()
    print(f"Connecting to {ServerConfig.IP}:{ServerConfig.PORT}...")

    try:
        with socket.create_connection((ServerConfig.IP, ServerConfig.PORT)) as sock:
            sock.settimeout(ProtocolConfig.TIMEOUT)
            
            with context.wrap_socket(sock) as secure_sock:
                print(f"Handshake successful with {secure_sock.getpeername()}")
                print(f"Using cipher: {secure_sock.cipher()}")
                print(f"SSL version: {secure_sock.version()}")

                if secure_sock.getpeercert(binary_form=True):
                    print("Client certificate was sent to the server")
                
                request = f"GET /resource HTTP/1.1\r\nHost: {ServerConfig.HOSTNAME}\r\n\r\n"
                secure_sock.sendall(request.encode())

                print("Receiving response...")
                response = b""
                total_received = 0
                
                # Read the response in chunks
                while True:
                    try:
                        size = 1024  # You might want to adjust this size
                        chunk = secure_sock.recv(size)
                        if not chunk:
                            break
                        response += chunk
                        total_received += len(chunk)
                        print(f"Received {len(chunk)} bytes (Total: {total_received})")
                    except socket.timeout:
                        print("Timeout - continuing...")
                        continue
                    except Exception as e:
                        print(f"Error receiving data: {e}")
                        if total_received == 0:
                            raise  # If no data was received, raise an error
                        break  # if partial data was received, continue the loop
                
                print(f"\nTotal bytes received: {total_received}")
                
                try:
                    print("\n=== Decoded Messages ===")
                    parts = response.split(b'--boundary')
                    for part in parts:
                        if b'Content-Type: text/plain' in part and b'\r\n\r\n' in part:
                            message = part.split(b'\r\n\r\n', 1)[1].strip()
                            if message:
                                print(f"Message: {message.decode('utf-8', errors='ignore')}")
                except Exception as e:
                    print(f"Error parsing response: {e}")

    except ssl.SSLError as e:
        print(f"SSL Error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print("\nConnection closed")

if __name__ == "__main__":
    client()
