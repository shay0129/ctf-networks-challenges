# client2.py
import socket
import ssl
import protocol

def send_all(sock, data):
    total_sent = 0
    while total_sent < len(data):
        sent = sock.send(data[total_sent:])
        if sent == 0:
            raise RuntimeError("Socket connection broken")
        total_sent += sent

def client():
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.set_ciphers('AES128-SHA256')
    context.load_cert_chain(certfile=protocol.Path+"client.crt", keyfile=protocol.Path+"client.key")
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=protocol.Path+"server.crt")  # Trust the server's self-signed cert

    try:
        with socket.create_connection(('localhost', protocol.SERVER_PORT)) as sock:
            with context.wrap_socket(sock, server_hostname='localhost') as secure_sock:
                print(f"Connected to {secure_sock.getpeername()}")
                print(f"Using cipher: {secure_sock.cipher()}")
                print(f"SSL version: {secure_sock.version()}")
                
                request = "GET /resource HTTP/1.1\r\nHost: localhost\r\n\r\n"
                print(f"Sending request: {request}")
                send_all(secure_sock, request.encode())
                
                # Receive initial response
                response = secure_sock.recv(4096).decode()
                print(f"Received: {response}")
                
                if "Please provide your CSR file" in response:
                    # Send CSR file
                    with open(protocol.Path+"client.csr", "r") as csr_file:
                        csr_content = csr_file.read()
                    print(f"Sending CSR file (length: {len(csr_content)} bytes)...")
                    send_all(secure_sock, csr_content.encode())
                    print("CSR file sent successfully.")
                    
                    # Receive final response
                    response = b""
                    while True:
                        chunk = secure_sock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                    print(f"Received final response: {response.decode()}")
                else:
                    print("Unexpected response from server")
                
    except ssl.SSLError as e:
        print(f"SSL Error: {e}")
    except socket.error as e:
        print(f"Socket Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    client()