"""
SSL Client Module
Implements secure client communication with SSL/TLS support.
"""
from protocol import ServerConfig, ProtocolConfig
import socket
import ssl
import logging
from typing import Optional

def create_client_ssl_context() -> ssl.SSLContext:
    """
    Create and configure SSL context for client.
    
    Returns:
        Configured SSL context with client certificates loaded
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.set_ciphers('AES128-SHA256')
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        context.load_cert_chain(certfile="client.crt", keyfile="client.key")
        logging.info("Client certificate and key loaded successfully")
    except Exception as e:
        logging.error(f"Error loading client certificate or key: {e}")
    
    return context

def receive_response(secure_sock: ssl.SSLSocket) -> Optional[bytes]:
    """
    Receive and accumulate response data from server.
    
    Args:
        secure_sock: Established SSL socket connection
        
    Returns:
        Complete response as bytes, or None if error occurs
    """
    response = b""
    total_received = 0
    
    while True:
        try:
            chunk = secure_sock.recv(1024)
            if not chunk:
                break
                
            response += chunk
            total_received += len(chunk)
            logging.debug(f"Received {len(chunk)} bytes (Total: {total_received})")
            
        except socket.timeout:
            logging.debug("Timeout - continuing...")
            continue
        except Exception as e:
            logging.error(f"Error receiving data: {e}")
            if total_received == 0:
                return None
            break
    
    logging.info(f"Total bytes received: {total_received}")
    return response

def parse_multipart_response(response: bytes) -> None:
    """
    Parse and display multipart response messages.
    
    Args:
        response: Raw response data containing multipart messages
    """
    try:
        logging.info("\n=== Decoded Messages ===")
        parts = response.split(b'--boundary')
        
        for part in parts:
            if b'Content-Type: text/plain' in part and b'\r\n\r\n' in part:
                message = part.split(b'\r\n\r\n', 1)[1].strip()
                if message:
                    logging.info(f"Message: {message.decode('utf-8', errors='ignore')}")
                    
    except Exception as e:
        logging.error(f"Error parsing response: {e}")

def client() -> None:
    """
    Main client function that establishes secure connection and handles communication.
    """
    context = create_client_ssl_context()
    logging.info(f"Connecting to {ServerConfig.IP}:{ServerConfig.PORT}...")

    try:
        with socket.create_connection((ServerConfig.IP, ServerConfig.PORT)) as sock:
            sock.settimeout(ProtocolConfig.TIMEOUT)
            
            with context.wrap_socket(sock) as secure_sock:
                logging.info(f"Handshake successful with {secure_sock.getpeername()}")
                logging.debug(f"Using cipher: {secure_sock.cipher()}")
                logging.debug(f"SSL version: {secure_sock.version()}")

                if secure_sock.getpeercert(binary_form=True):
                    logging.info("Client certificate was sent to the server")
                
                # Send request
                request = (
                    f"GET /resource HTTP/1.1\r\n"
                    f"Host: {ServerConfig.HOSTNAME}\r\n"
                    f"\r\n"
                )
                secure_sock.sendall(request.encode())
                logging.info("Request sent, awaiting response...")

                # Receive and process response
                response = receive_response(secure_sock)
                if response:
                    parse_multipart_response(response)

    except ssl.SSLError as e:
        logging.error(f"SSL Error: {e}")
    except Exception as e:
        logging.error(f"An error occurred: {e}")
    finally:
        logging.info("Connection closed")

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    client()