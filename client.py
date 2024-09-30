# client.py
# Basic HTTP GET Client
# client1.py
import socket
import ssl
import protocol

def main():
    # Initialize the socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Create SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.set_ciphers('AES128-SHA256')
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    print(f"Connecting to {protocol.CLIENT_IP}:{protocol.SERVER_PORT}")
    
    try:
        with context.wrap_socket(sock, server_hostname='localhost') as secure_sock:
            secure_sock.connect((protocol.CLIENT_IP, protocol.SERVER_PORT))
            
            print(f"Connected with cipher: {secure_sock.cipher()}")
            print(f"SSL version: {secure_sock.version()}")
            
            # Send HTTP GET request
            request = "GET /resource HTTP/1.1\r\nHost: localhost\r\n\r\n"
            secure_sock.send(request.encode())
            print(f"Sent: {request}")
            
            # Wait for server response
            response = secure_sock.recv(1024).decode()
            print(f"Received: {response}")
    
    except ssl.SSLError as e:
        print(f"SSL Error: {e}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()

if __name__ == '__main__':
    main()