# client1.py
import socket
import ssl
import protocol

def main():
    # Initialize the socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Wrap the socket with SSL
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Don't verify the server's certificate

    print(f"Connecting to {'127.0.0.1'}:{protocol.SERVER_PORT}")
    
    try:
        with context.wrap_socket(sock, server_hostname='localhost') as secure_sock:
            secure_sock.connect(('127.0.0.1', protocol.SERVER_PORT))
            
            # Send a "Hello" message to the server
            message = "Hello"
            secure_sock.send(message.encode())
            print(f"Sent: {message}")

            # Receive a response from the server
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