# basic_client.py
import socket
import ssl
import protocol
import sys
import time
import os
# pyinstaller --onefile basic_client.py
def create_hint_file():
    hint = """CTF_CHALLENGE_HINT:
Python SSL Socket Template:

# 1. Create SSL Context
- context = ssl.SSLContext(ssl.PROTOCOL_TLSv...?)
- cipher: (...?)
- trust_chain = ...?  # Server is very picky about this!

# 2. Create Socket & SSL Wrap
- socket.create_connection()
- context.wrap_socket(socket)

# 3. Send HTTP Request

# 4. Receive Responses

# 5. Close Connection

    Good luck!"""
    
    user_home = os.path.expanduser('~')
    ctf_temp_dir = os.path.join(user_home, 'CTF_TEMP')
    os.makedirs(ctf_temp_dir, exist_ok=True)  # Create CTF_TEMP directory if it doesn't exist
    hint_file_path = os.path.join(ctf_temp_dir, 'ctf_hint.txt')
    with open(hint_file_path, 'w') as f:
        f.write(hint)
    return hint_file_path

def create_client_ssl_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.set_ciphers('AES128-SHA256')
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Disable server cert verification for simplicity
    return context

def main():
    # Create a hint file
    try:
        hint_file = create_hint_file()
    except Exception as e:
        hint_file = None


    # Initialize the socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Create SSL context
    context = create_client_ssl_context()
    
    server_address = (protocol.SERVER_IP, protocol.SERVER_PORT)
    #print(f"Connecting to {server_address[0]}:{server_address[1]}...")
    
    try:
        # Wrap the socket with SSL and connect
        with context.wrap_socket(sock, server_hostname=protocol.SERVER_HOSTNAME) as secure_sock:
            secure_sock.connect(server_address)
            #print("SSL/TLS handshake completed")
            
            # Send HTTP GET request over the secure connection
            request = f"GET /resource HTTP/1.1\r\nHost: {protocol.SERVER_HOSTNAME}\r\n\r\n"
            secure_sock.send(request.encode())
            
            # Wait for server response
            response = secure_sock.recv(4096).decode()
            #print("Server response:", response)
            """HTTP/1.1 400 Bad Request
            No client certificate provided"""

    except Exception as e:
        None # Ignore connection errors
    finally:
        sock.close()
        #print("Connection closed")


    # Add delay at the end
    for i in range(30, 0, -1):
        sys.stdout.write(f"\rTime remaining: {i} seconds")
        sys.stdout.flush()
        time.sleep(1)


    # Delete the hint file
    if hint_file and os.path.exists(hint_file):
        try:
            os.remove(hint_file)
            # Optionally, remove the CTF_TEMP directory if it's empty
            os.rmdir(os.path.dirname(hint_file))
        except Exception as e:
            print(f"Cleanup error: {e}")

if __name__ == '__main__':
    main()