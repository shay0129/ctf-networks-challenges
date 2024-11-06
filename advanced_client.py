import socket
import ssl
import protocol

def create_client_ssl_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.set_ciphers('AES128-SHA256')

    # Load the client certificate and private key
    try:
        context.load_cert_chain(certfile="../certificates/client.crt", keyfile="../certificates/client.key")
        print("Client certificate and key loaded successfully")
    except Exception as e:
        print(f"Error loading client certificate or key: {e}")

    # Disable server cert verification for self-signed certs
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Disable server cert verification

    return context
def client():
    context = create_client_ssl_context()
    print(f"Connecting to {protocol.SERVER_IP}:{protocol.SERVER_PORT}")

    try:
        with socket.create_connection((protocol.SERVER_IP, protocol.SERVER_PORT)) as sock:
            # הגדרת timeout ארוך יותר
            sock.settimeout(30)
            
            with context.wrap_socket(sock) as secure_sock:
                print(f"Handshake successful with {secure_sock.getpeername()}")
                print(f"Using cipher: {secure_sock.cipher()}")
                print(f"SSL version: {secure_sock.version()}")

                if secure_sock.getpeercert(binary_form=True):
                    print("Client certificate was sent to the server")
                
                request = f"GET /resource HTTP/1.1\r\nHost: {protocol.SERVER_HOSTNAME}\r\n\r\n"
                secure_sock.sendall(request.encode())

                print("Receiving response...")
                response = b""
                total_received = 0
                
                # קריאת המידע בחלקים קטנים יותר
                while True:
                    try:
                        chunk = secure_sock.recv(1024)  # קריאה של חלקים קטנים יותר
                        if not chunk:
                            break
                        response += chunk
                        total_received += len(chunk)
                        print(f"Received {len(chunk)} bytes (Total: {total_received})")
                    except socket.timeout:
                        print("Timeout - continuing...")
                        continue
                    except Exception as e:
                        if total_received == 0:
                            raise  # אם לא קיבלנו כלום, נזרוק את השגיאה
                        break  # אם קיבלנו חלק מהמידע, נמשיך לעיבוד
                
                print(f"\nTotal bytes received: {total_received}")
                
                try:
                    print("\n=== Decoded Messages ===")
                    parts = response.split(b'--boundary')
                    for part in parts:
                        if b'Content-Type: text/plain' in part and b'\r\n\r\n' in part:
                            message = part.split(b'\r\n\r\n', 1)[1].strip()
                            if message:
                                print(f"Messsage: {message.decode('utf-8', errors='ignore')}")
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