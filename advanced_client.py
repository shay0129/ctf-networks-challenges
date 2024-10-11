# advanced_client.py
import socket
import ssl
import protocol

def main():
    # Initialize the socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Create SSL context

    #context = ssl.create_default_context()
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.set_ciphers('AES128-SHA256')
    context.load_cert_chain(certfile="client.crt", keyfile="client.key")
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Disable server cert verification for simplicity

    server_address = (protocol.SERVER_IP, protocol.SERVER_PORT)
    print(f"Connecting to {server_address[0]}:{server_address[1]}...")
    
    try:
        with context.wrap_socket(sock, server_hostname=protocol.SERVER_HOSTNAME) as secure_sock:
            secure_sock.connect(server_address)
            print(f"Connected with cipher: {secure_sock.cipher()}")
            print(f"SSL version: {secure_sock.version()}")
            
            # Send HTTP GET request
            request = f"GET /resource HTTP/1.1\r\nHost: {protocol.SERVER_HOSTNAME}\r\n\r\n"
            secure_sock.send(request.encode())
            print(f"Sent: {request}")
            
            # Wait for server response
            response = secure_sock.recv(4096).decode()
            print(f"Received: {response}")
    
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        sock.close()
        print("Connection closed")

if __name__ == '__main__':
    main()