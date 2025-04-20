"""
Certificate Authority Server Utilities
Provides functions for SSL certificate operations, CSR handling, and HTTP parsing.
"""
from typing import Tuple, Optional, Dict, Union, NamedTuple
from socket import socket
import random
import logging
import ssl
import time
import traceback

from urllib.parse import urlparse, parse_qs, urlencode
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from OpenSSL import crypto

from ..protocol import ProtocolConfig

class ParsedRequest(NamedTuple):
    """Structure for parsed HTTP request data"""
    method: bytes
    path: bytes
    version: bytes
    query_params: Dict[str, list]
    headers: Dict[bytes, bytes]
    body: bytes

def sign_csr_with_ca(csr_pem: bytes, ca_key_pem: bytes, ca_cert_pem: bytes) -> Optional[bytes]:
    """
    Sign a CSR using CA's private key with validation.

    Args:
        csr_pem: CSR in PEM format
        ca_key_pem: CA private key in PEM format
        ca_cert_pem: CA certificate in PEM format (optional for self-signing)

    Returns:
        Signed certificate in PEM format
    """
    try:
        if not ca_key_pem or not ca_cert_pem:
            raise ValueError("Missing CA key or certificate")
            
        # Validate CA private key
        try:
            ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_key_pem)
        except Exception:
            raise ValueError("Invalid CA private key")

        # Load and validate CSR
        csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_pem)
        cert = crypto.X509()
        cert.set_subject(csr.get_subject())
        cert.set_pubkey(csr.get_pubkey())
        cert.set_serial_number(random.getrandbits(64))
        
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(31536000)  # 1 year

        # Set certificate issuer
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_pem)
        cert.set_issuer(ca_cert.get_subject())
        
        # Sign certificate
        cert.sign(ca_key, 'sha512')
        return crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

    except Exception as e:
        logging.error(f"Error signing CSR: {e}")
        return None

def download_file(file_name: str, content: Union[str, bytes]) -> bool:
    """ Save content to file with error handling. """
    try:
        with open(file_name, "wb") as f:
            if isinstance(content, str):
                f.write(content.encode())
            else:
                f.write(content)
        logging.info(f"File saved to {file_name}")
        return True
    except (IOError, OSError) as e:
        logging.error(f"Error saving file {file_name}: {e}")
        return False

def parse_http_headers(raw_data: bytes) -> Tuple[Optional[Dict[bytes, bytes]], bytes, Optional[int]]:
    """
    Parse raw HTTP headers with improved URL handling.
    
    Args:
        raw_data: Raw HTTP request data
        
    Returns:
        Tuple of (headers dict, body, content length)
    """
    try:
        header_part, body = raw_data.split(b'\r\n\r\n', 1)
        header_lines = header_part.split(b'\r\n')
        
        # Parse first line for request info
        first_line = header_lines[0].split(b' ')
        if len(first_line) >= 3:
            method, raw_url, version = first_line
            # Parse URL using urlparse
            parsed_url = urlparse(raw_url.decode('utf-8'))
            
            headers = {
                b'request_method': method,
                b'request_path': parsed_url.path.encode(),
                b'request_version': version
            }
            
            # Add query parameters if present
            if parsed_url.query:
                headers[b'request_query'] = parsed_url.query.encode()
                query_params = parse_qs(parsed_url.query)
                for key, value in query_params.items():
                    headers[f'query_{key}'.encode()] = value[0].encode()
                    
        # Parse remaining headers
        for line in header_lines[1:]:
            if b':' in line:
                key, value = line.split(b':', 1)
                headers[key.strip().lower()] = value.strip()

        content_length = None
        if b'content-length' in headers:
            try:
                content_length = int(headers[b'content-length'])
            except ValueError:
                logging.warning("Invalid Content-Length header")

        return headers, body, content_length
        
    except Exception as e:
        logging.error(f"Error parsing HTTP headers: {e}")
        #traceback.print_exc()
        return None, b"", None

def parse_http_request(data: bytes) -> Optional[ParsedRequest]:
    """
    Parse raw HTTP request with improved URL and query parameter handling.
    
    Args:
        data: Raw HTTP request data
        
    Returns:
        ParsedRequest object containing parsed request components or None if parsing fails
    """
    try:
        if len(data) > ProtocolConfig.MAX_REQUEST_SIZE:
            logging.error(f"Request size {len(data)} exceeds maximum {ProtocolConfig.MAX_REQUEST_SIZE}")
            return None

        headers_raw, body = data.split(b'\r\n\r\n', 1)
        header_lines = headers_raw.split(b'\r\n')
        
        # Parse request line
        method, raw_url, version = header_lines[0].split(b' ', 2)
        
        # Parse URL using urlparse
        parsed_url = urlparse(raw_url.decode('utf-8'))
        path = parsed_url.path.encode()
        
        # Parse query parameters
        query_params = parse_qs(parsed_url.query) if parsed_url.query else {}
        
        # Parse headers
        headers = {}
        for line in header_lines[1:]:
            if b':' in line:
                key, value = line.split(b':', 1)
                headers[key.strip().lower()] = value.strip()
        
        # Add parsed URL components to headers
        headers.update({
            b'request_method': method,
            b'request_path': path,
            b'request_version': version,
            b'request_scheme': parsed_url.scheme.encode() if parsed_url.scheme else b'',
            b'request_netloc': parsed_url.netloc.encode() if parsed_url.netloc else b'',
            b'request_query': parsed_url.query.encode() if parsed_url.query else b'',
            b'request_fragment': parsed_url.fragment.encode() if parsed_url.fragment else b''
        })
        
        return ParsedRequest(
            method=method,
            path=path,
            version=version,
            query_params=query_params,
            headers=headers,
            body=body
        )
        
    except Exception as e:
        logging.error(f"Error parsing HTTP request: {e}")
        #traceback.print_exc()
        return None

def format_response_with_query(status_line: bytes, response_data: Dict[str, str], 
                             content_type: bytes = b"application/x-www-form-urlencoded") -> bytes:
    """
    Format response with query parameters.
    
    Args:
        status_line: HTTP status line
        response_data: Dictionary of response data
        content_type: Response content type
        
    Returns:
        Formatted response as bytes
    """
    body = urlencode(response_data).encode()
    content_length = str(len(body)).encode()
    
    response = [
        status_line,
        b"Content-Type: " + content_type,
        b"Content-Length: " + content_length,
        b"Connection: close",
        b"",
        body
    ]
    
    return b"\r\n".join(response)

def format_error_response(status_line: bytes, error_msg: Union[str, bytes], 
                         close_connection: bool = True) -> bytes:
    """
    Format error response with connection handling.

    Args:
        status_line: HTTP status line
        error_msg: Error message
        close_connection: Whether to close the connection

    Returns:
        Formatted error response as bytes
    """
    error_msg_bytes = error_msg.encode('utf-8') if isinstance(error_msg, str) else error_msg
    content_length = str(len(error_msg_bytes)).encode('utf-8')
    
    response = [
        status_line,
        b"Content-Type: text/plain",
        b"Content-Length: " + content_length,
    ]
    
    if close_connection:
        response.append(b"Connection: close")
    
    response.extend([b"", b""])
    return b"\r\n".join(response) + error_msg_bytes

def verify_client_csr(csr_data: bytes) -> Optional[crypto.X509Req]:
    """
    Verify CSR signature and format.

    Args:
        csr_data: CSR data in PEM format

    Returns:
        Verified CSR object or None if invalid
    """
    try:
        if not csr_data.startswith(b"-----BEGIN CERTIFICATE REQUEST-----"):
            logging.error("Invalid CSR format")
            return None
            
        csr_obj = x509.load_pem_x509_csr(csr_data, default_backend())
        csr_obj.public_key().verify(
            csr_obj.signature,
            csr_obj.tbs_certrequest_bytes,
            asymmetric_padding.PKCS1v15(),
            csr_obj.signature_hash_algorithm,
        )
        
        logging.info("CSR verification successful")
        return csr_obj
    except Exception as e:
        logging.error(f"CSR verification failed: {e}")
        return None

def validate_certificate(cert_data: bytes) -> bool:
    """
    Validate certificate PEM format.

    Args:
        cert_data: Certificate data to validate

    Returns:
        True if valid PEM format, False otherwise
    """
    return (cert_data.startswith(b"-----BEGIN CERTIFICATE-----") and 
            cert_data.endswith(b"-----END CERTIFICATE-----\n"))

def receive_all(sock: socket, expected_length: Optional[int] = None,
                timeout: float = ProtocolConfig.READ_TIMEOUT) -> bytes:
    """
    Receive all data with timeout handling.

    Args:
        sock: Socket to receive data from
        expected_length: Expected content length (optional)
        timeout: Read timeout in seconds

    Returns:
        Received data as bytes
    """
    data = b""
    end_time = time.time() + timeout
    
    while time.time() < end_time:
        try:
            sock.settimeout(end_time - time.time())
            chunk = sock.recv(ProtocolConfig.MAX_MSG_LENGTH)
            if not chunk:
                break
            data += chunk
            if expected_length and len(data) >= expected_length:
                break
        except socket.timeout:
            break
    
    return data

def monitor_content_length(actual_size: int, declared_size: int, source: str, direction: str) -> bool:
    """
    Monitor and log content length differences.
    
    Args:
        actual_size: Actual content size in bytes
        declared_size: Declared Content-Length value
        source: Source identifier ('CLIENT' or 'SERVER')
        direction: Direction identifier ('SENT' or 'RECEIVED')
        
    Returns:
        True if sizes match, False otherwise
    """
    logging.info(f"\n=== Content Length Monitor ===")
    logging.info(f"Source: {source}")
    logging.info(f"Direction: {direction}")
    logging.info(f"Declared Content-Length: {declared_size}")
    logging.info(f"Actual Size: {actual_size}")
    
    if actual_size != declared_size:
        #logging.warning(f"Size mismatch detected!")
        return False
    else:
        #logging.info("Status: MATCH")
        return True

def read_http_request(ssl_socket: ssl.SSLSocket) -> Tuple[Optional[Dict[bytes, bytes]], bytes]:
    """
    Read and parse HTTP request from SSL socket.

    Args:
        ssl_socket: SSL socket to read from

    Returns:
        Tuple containing headers and body
    """
    request_data = b""
    while b'\r\n\r\n' not in request_data:
        chunk = ssl_socket.recv(4096)
        if not chunk:
            break
        request_data += chunk

    parsed = parse_http_request(request_data)
    if parsed:
        return parsed.headers, parsed.body
    return None, b""

def read_request_body(ssl_socket: ssl.SSLSocket, initial_body: bytes, content_length: int) -> bytes:
    """
    Read complete request body with improved error handling and size limits.

    Args:
        ssl_socket: SSL socket to read from
        initial_body: Initial part of body already read
        content_length: Expected content length

    Returns:
        Complete request body

    Raises:
        ValueError: If content length exceeds maximum
        TimeoutError: If read timeout occurs
    """
    if content_length > ProtocolConfig.MAX_BODY_SIZE:
        raise ValueError(f"Content length {content_length} exceeds maximum allowed size")
        
    body = initial_body
    bytes_remaining = content_length - len(initial_body)
    timeout = time.time() + ProtocolConfig.READ_TIMEOUT
    
    while bytes_remaining > 0 and time.time() < timeout:
        chunk_size = min(4096, bytes_remaining)
        chunk = ssl_socket.recv(chunk_size)
        if not chunk:
            break
        body += chunk
        bytes_remaining -= len(chunk)
    
    if bytes_remaining > 0:
        raise TimeoutError("Timeout while reading request body")
        
    return body

def send_error_response(ssl_socket: ssl.SSLSocket, status: bytes, message: bytes) -> None:
    """
    Send an error response to the client.

    Args:
        ssl_socket: SSL socket to send response to
        status: HTTP status line
        message: Error message
    """
    response = format_error_response(status, message)
    ssl_socket.sendall(response)