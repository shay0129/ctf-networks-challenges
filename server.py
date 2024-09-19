import socket
import ssl
import threading
import protocol

connection_event = threading.Event()

def print_encryption_key():
    if not connection_event.wait(5):
        print(f"Encryption Key: {protocol.ENCRYPTION_KEY}")
        return False
    return True

def handle_client_request(current_socket):
    try:
        # Check for client certificate
        cert = current_socket.getpeercert()
        if cert:
            print("Client certificate received")
            response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
            response += "FLAG{This_Is_Your_Secret_Flag}"
        else:
            print("No client certificate provided")
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\n"
            response += "Hint: Use a self-signed certificate (Country: IL, CN: Pasdaran.local) to access the resource."
        
        return response
    except Exception as e:
        print(f"Error handling client: {e}")
        return "HTTP/1.1 500 Internal Server Error\r\n\r\n"

def main():
    # Set up SSL context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    context.verify_mode = ssl.CERT_OPTIONAL  # Allow optional client cert

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((protocol.SERVER_IP, protocol.SERVER_PORT))
    server_socket.listen(5)
    server_socket.settimeout(5)  # Set timeout for 5 seconds

    print("Server is up and running, waiting for a client...")

    # Start a thread to print the encryption key if no connection is made in 5 seconds
    if not print_encryption_key():
        server_socket.close()
        return

    try:
        client_socket, client_address = server_socket.accept()
        print(f"Client connected from {client_address}")

        ssl_socket = context.wrap_socket(client_socket, server_side=True)

        # Check for client certificate
        cert = ssl_socket.getpeercert()
        if not cert:
            print("No client certificate provided.")
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\n"
            response += "Hint: Use a self-signed certificate (Country: IL, CN: Pasdaran.local) to access the resource."
            ssl_socket.send(response.encode())
            ssl_socket.close()
            return

        # Handle client request
        data = ssl_socket.recv(protocol.MAX_MSG_LENGTH).decode()
        print(f"Client sent: {data}")
        
        response = handle_client_request(ssl_socket)
        ssl_socket.send(response.encode())

        ssl_socket.close()
    except socket.timeout:
        print("No client connected within 5 seconds. Server is stopping.")
    finally:
        server_socket.close()

if __name__ == '__main__':
    main()
