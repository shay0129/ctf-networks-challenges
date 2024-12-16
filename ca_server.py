""" CA Server for signing client CSRs

Initialize CA with details:
country="IR",
state="Tehran",
city="Tehran",
org_name="IRGC",
org_unit="Cybersecurity",
domain_name="IRGC Root CA"
"""

import traceback
import socket
import ssl
import logging
from typing import Optional
from protocol import CAConfig
import time
from ca_server_utils import (
    create_ca_server_ssl_context,
    verify_client_csr,
    sign_csr_with_ca,
    format_error_response,
    parse_http_headers,
    parse_http_request,
    create_csr,
    download_file,
    validate_certificate
)

def receive_certificate(secure_sock: ssl.SSLSocket, timeout: int = 30, debug: bool = False) -> Optional[bytes]:
    try:
        secure_sock.settimeout(timeout)
        full_response = b""
        total_received = 0

        while True:
            try:
                chunk = secure_sock.recv(8192)
                if not chunk:
                    logging.info("Connection closed by server")
                    break
                    
                full_response += chunk
                total_received += len(chunk)
                
                # Add debug print to see the full response
                print("=== Full Server Response ===")
                print(full_response.decode('utf-8', errors='replace'))
                print("==========================")

                headers, body, content_length = parse_http_headers(full_response)
                
                if headers is None:
                    continue
                    
                if content_length is None:
                    logging.error("Invalid or missing Content-Length")
                    return None
                    
                body_bytes = body.encode('utf-8')
                if len(body_bytes) < content_length:
                    continue
                    
                if len(body_bytes) == content_length:
                    if validate_certificate(body_bytes):
                        logging.info(f"Valid certificate received ({len(body_bytes)} bytes)")
                        return body_bytes
                    else:
                        logging.error(f"Invalid certificate format\nReceived body:\n{body}")
                        return None
                else:
                    logging.error("Response body length mismatch")
                    return None
                    
            except ssl.SSLWantReadError:
                time.sleep(0.1)
                continue
            except TimeoutError:
                logging.warning("Socket timeout")
                break
            except Exception as e:
                logging.error(f"Error receiving data: {e}")
                break
                
    except Exception as e:
        logging.error(f"Fatal error in receive_certificate: {e}")
        
    return None


def handle_client_request(ssl_socket, ca_cert_pem, ca_key_pem) -> bool:
    """Handle client request to sign a CSR"""
    
    try:
        # Receive the initial request data
        request_data = b""
        while b'\r\n\r\n' not in request_data:
            chunk = ssl_socket.recv(4096)
            if not chunk:
                return False
            request_data += chunk

        # Parse HTTP headers
        headers, initial_body = parse_http_request(request_data)
        if not headers:
            response = format_error_response(
                b"HTTP/1.1 400 Bad Request",
                b"Invalid HTTP request"
            )
            ssl_socket.sendall(response)
            return False

        # Verify request method and path
        if headers.get(b'request_method') != b'POST':
            response = format_error_response(
                b"HTTP/1.1 405 Method Not Allowed",
                b"Only POST method is allowed"
            )
            ssl_socket.sendall(response)
            return False

        # Get Content-Length
        try:
            content_length = int(headers.get(b'content-length', b'0'))
        except ValueError:
            response = format_error_response(
                b"HTTP/1.1 400 Bad Request",
                b"Invalid Content-Length"
            )
            ssl_socket.sendall(response)
            return False
        
        # Read remaining body data if necessary
        body = initial_body
        while len(body) < content_length:
            chunk = ssl_socket.recv(min(4096, content_length - len(body)))
            if not chunk:
                break
            body += chunk

        if not body:
            response = format_error_response(
                b"HTTP/1.1 400 Bad Request",
                b"No CSR provided"
            )
            ssl_socket.sendall(response)
            return False

        # Verify and process CSR
        csr_obj = verify_client_csr(body)
        if not csr_obj:
            response = format_error_response(
                b"HTTP/1.1 403 Forbidden",
                b"Invalid CSR"
            )
            ssl_socket.sendall(response)
            return False

        # Sign the CSR
        crt_file = sign_csr_with_ca(csr_pem=body, ca_key_pem=ca_key_pem, ca_cert_pem=ca_cert_pem)
        if not crt_file:
            response = format_error_response(
                b"HTTP/1.1 500 Internal Server Error",
                b"Certificate signing failed"
            )
            ssl_socket.sendall(response)
            return False

        # Prepare successful response
        content_length = str(len(crt_file)).encode('utf-8')
        response_headers = [
            b"HTTP/1.1 200 OK",
            b"Content-Type: application/x-pem-file",
            b"Content-Length: " + content_length,
            b"Connection: close",
            b"",
            b""
        ]
        
        # Create full response
        response = b"\r\n".join(response_headers) + crt_file
        
        # Debug logging
        print("=== Response Debug Info ===")
        headers_length = len(b"\r\n".join(response_headers))
        print(f"Headers length: {headers_length} bytes")
        print(f"Certificate length: {len(crt_file)} bytes")
        print(f"Total response length: {len(response)} bytes")
        print("Headers:")
        try:
            print(b"\r\n".join(response_headers).decode('utf-8'))
        except UnicodeDecodeError:
            print("(Unable to decode headers)")
        print("=========================")
        
        # Send complete response
        try:
            ssl_socket.sendall(response)
            print(f"Total response sent: {len(response)} bytes")
            print("Certificate sent successfully")
            return True
            
        except Exception as send_error:
            print(f"Error sending response: {send_error}")
            traceback.print_exc()
            return False

    except Exception as e:
        print(f"Error handling client request: {e}")
        traceback.print_exc()
        response = format_error_response(
            b"HTTP/1.1 500 Internal Server Error",
            b"Internal server error"
        )
        try:
            ssl_socket.sendall(response)
        except:
            pass
        return False


def main():    
    # Create CSR with the correct domain name
    download_file("ca.crt", CAConfig.CERT)
    #download_file("ca.key", CAConfig.KEY)

    # Convert cert and key to bytes once
    cert_bytes = CAConfig.CERT.encode() if isinstance(CAConfig.CERT, str) else CAConfig.CERT
    key_bytes = CAConfig.KEY.encode() if isinstance(CAConfig.KEY, str) else CAConfig.KEY
    
    context = create_ca_server_ssl_context(cert_bytes, key_bytes)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((CAConfig.IP, CAConfig.PORT))
        server_socket.listen(5)

        print(f"Server listening on {CAConfig.IP}:{CAConfig.PORT}")

        try:
            while True:
                client_socket, addr = server_socket.accept()
                print(f"Client connected: {addr}")

                try:
                    with context.wrap_socket(client_socket, server_side=True) as ssl_socket:
                        handle_client_request(ssl_socket, cert_bytes, key_bytes)
                except ssl.SSLError as e:
                    print(f"SSL error: {e}")
        except KeyboardInterrupt:
            print("\nShutting down the server.")
        finally:
            print("Server stopped.")

if __name__ == "__main__":
    main()