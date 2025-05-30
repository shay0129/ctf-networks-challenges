# pyright: ignore[reportUnusedFunction]
"""
Certificate Authority Server Utilities
Provides functions for SSL certificate operations, CSR handling, and HTTP parsing.
"""
from typing import Tuple, Optional, Dict, Union, NamedTuple, List
from socket import socket, timeout as socket_timeout
import random
import logging
import ssl
import time

from urllib.parse import urlparse, parse_qs, urlencode
from OpenSSL import crypto

from ..protocol import ProtocolConfig, PADDING_MARKER

class ParsedRequest(NamedTuple):
    """Structure for parsed HTTP request data"""
    method: bytes
    path: bytes
    version: bytes
    query_params: Dict[str, List[str]]
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
        cert.gmtime_adj_notAfter(31536000)   # 1 year

        # Set certificate issuer
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_pem)
        cert.set_issuer(ca_cert.get_subject())

        # Sign certificate
        cert.sign(ca_key, 'sha512')
        return crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

    except Exception:
        # logging.error(f"Error signing CSR: {e}")
        return None

def download_file(file_name: str, content: Union[str, bytes]) -> bool:
    """ Save content to file with error handling. """
    try:
        with open(file_name, "wb") as f:
            if isinstance(content, str):
                f.write(content.encode())
            else:
                f.write(content)
        #logging.info(f"File saved to {file_name}")
        return True
    except (IOError, OSError):
        ## logging.error(f"Error saving file {file_name}: {e}")
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
        headers: Dict[bytes, bytes] = {}
        # Parse first line for request info
        first_line = header_lines[0].split(b' ')
        if len(first_line) >= 3:
            method, raw_url, version = first_line
            # Parse URL using urlparse
            parsed_url = urlparse(raw_url.decode('utf-8'))
            headers[b'request_method'] = method
            headers[b'request_path'] = parsed_url.path.encode()
            headers[b'request_version'] = version
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
        
    except Exception:
        # logging.error(f"Error parsing HTTP headers: {e}")
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
            # logging.error(f"Request size {len(data)} exceeds maximum {ProtocolConfig.MAX_REQUEST_SIZE}")
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
        headers: Dict[bytes, bytes] = {}
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
        
    except Exception:
        # logging.error(f"Error parsing HTTP request: {e}")
        return None

def format_response_with_query(status_line: bytes, response_data: Dict[str, str], 
                             content_type: bytes = b"application/x-www-form-urlencoded") -> bytes:
    """ Format response with query parameters. """
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
    """ Format error response with connection handling. """
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

def verify_client_csr(csr_data: bytes, client_socket: ssl.SSLSocket) -> Optional[Tuple[crypto.X509Req, str]]:
    """ Verify CSR signature and format. """
    try:
        if not csr_data.startswith(b"-----BEGIN CERTIFICATE REQUEST-----"):
            # logging.error("Invalid CSR format - missing begin marker")
            return None
            
        # Load and verify CSR
        try:
            csr_obj = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_data)
            if not csr_obj:
                # logging.error("Failed to load CSR - null object returned")
                send_error_response(client_socket, b"HTTP/1.1 403 Forbidden", b"Invalid CSR")
                return None
        except Exception:
            # logging.error(f"Exception loading CSR: {cert_error}")
            send_error_response(client_socket, b"HTTP/1.1 403 Forbidden", b"Error parsing CSR")
            return None
        # Verify CSR signature
        if not csr_obj.verify(csr_obj.get_pubkey()):
            # logging.error("CSR signature verification failed")
            send_error_response(client_socket, b"HTTP/1.1 403 Forbidden", b"CSR signature verification failed")
            return None
    except Exception:
        # logging.error(f"CSR verification failed: {e}")
        return None

def read_client_name_response(client_socket: ssl.SSLSocket, timeout: int = 10) -> Optional[str]:
    """Read client's name response with timeout"""
    try:
        # Set a timeout to avoid hanging indefinitely
        client_socket.settimeout(timeout)
        
        request_data = b""
        start_time = time.time()
        # Keep reading until we get \r\n\r\n or a simple newline
        while time.time() - start_time < timeout:
            try:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                request_data += chunk
                
                # Check for HTTP request format
                if b'\r\n\r\n' in request_data:
                    parsed = parse_http_request(request_data)
                    if parsed:
                        return parsed.body.decode('utf-8').strip()
                    else:
                        # Try to extract name from raw data if HTTP parsing fails
                        name_part = request_data.split(b'\r\n\r\n')[-1].strip()
                        return name_part.decode('utf-8')
                
                # Check for simple newline-terminated input
                if b'\n' in request_data:
                    # Assume it's just a simple name entry
                    return request_data.strip().decode('utf-8')
            except socket_timeout:
                break
        
        return None
    finally:
        # Reset the timeout to the default value
        client_socket.settimeout(None)

def _extract_csr(ssl_socket: ssl.SSLSocket, headers: Dict[bytes, bytes], initial_body: bytes) -> Tuple[bool, Optional[Tuple[bytes, int]]]:  # noqa: F401, pylint: disable=unused-function
    """
    [INTERNAL/RESERVED] Extract CSR and checksum from request body without validation.
    This function is retained for possible future use or for reference in CSR handling logic.
    """
    try:
        # Extract Content-Length from headers
        content_length_header: bytes = headers.get(b'content-length', b'0')
        declared_length = int(content_length_header)
        
        # Read complete request body
        body = read_request_body(ssl_socket, initial_body, declared_length)
        
        # Locate the padding marker
        if PADDING_MARKER not in body:
            logging.warning("Padding marker not found in request body")
            send_error_response(ssl_socket, b"HTTP/1.1 400 Bad Request", b"Invalid CSR format: missing padding marker")
            return False, None
            
        # Split the body by the padding marker
        csr_part, checksum_part = body.split(PADDING_MARKER, 1)
        
        # Handle newlines correctly
        csr_part = _normalize_csr_newlines(csr_part)
        
        # Extract the embedded length
        try:
            # Clean non-numeric characters before parsing
            checksum_text = checksum_part.decode('utf-8').strip()
            # Remove any non-digit characters
            cleaned_checksum = ''.join(c for c in checksum_text if c.isdigit())
            embedded_length = int(cleaned_checksum)
            return True, (csr_part, embedded_length)
        except ValueError:
            logging.warning(f"Could not parse embedded length from: {checksum_part!r}")
            send_error_response(ssl_socket, b"HTTP/1.1 400 Bad Request", b"Invalid CSR format: checksum not a number")
            return False, None
            
    except ValueError:
        logging.warning("Invalid Content-Length header")
        send_error_response(ssl_socket, b"HTTP/1.1 400 Bad Request", b"Invalid Content-Length")
        return False, None
    except Exception:
        # logging.error(f"Error extracting CSR: {str(e)}")
        send_error_response(ssl_socket, b"HTTP/1.1 500 Internal Server Error", b"Internal server error during CSR extraction")
        return False, None

def _normalize_csr_newlines(csr_part: bytes) -> bytes:
        """Handle the newline issue with CSR by normalizing newlines"""
        if csr_part.endswith(b'\r\n'):
            # If CRLF ending, trim everything except the last CRLF
            temp_csr = csr_part.rstrip(b'\r\n \t')
            return temp_csr + b'\r\n'
        elif csr_part.endswith(b'\n'):
            # If LF ending, trim everything except the last LF
            temp_csr = csr_part.rstrip(b'\r\n \t')
            return temp_csr + b'\n'
        else:
            # If no newline at end, don't change anything
            return csr_part
        
def _validate_csr_checksum(original_csr: bytes, embedded_length: int) -> bool:  # noqa: F401, pylint: disable=unused-function
    """
    [INTERNAL/RESERVED] Validate that the CSR length matches the embedded checksum.
    This function is retained for possible future use or for reference in CSR validation logic.
    """
    actual_length = len(original_csr)
    if actual_length != embedded_length:
        logging.warning(f"CSR length mismatch: {actual_length} != {embedded_length}")
        return False
    logging.debug(f"CSR length verified: {actual_length} == {embedded_length}")
    return True

def validate_certificate(cert_data: bytes) -> bool:
    """ Validate certificate PEM format. """
    return (cert_data.startswith(b"-----BEGIN CERTIFICATE-----") and 
            cert_data.endswith(b"-----END CERTIFICATE-----\n"))

def receive_all(sock: socket, expected_length: Optional[int] = None,
                timeout: float = ProtocolConfig.READ_TIMEOUT) -> bytes:
    """ Receive all data with timeout handling. """
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
        except socket_timeout:
            break
    
    return data


def read_http_request(ssl_socket: ssl.SSLSocket) -> Tuple[Optional[Dict[bytes, bytes]], bytes]:
    """ Read and parse HTTP request from SSL socket. """
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
    """ Read complete request body with improved error handling and size limits. """

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
    """ Send an error response to the client. """
    response = format_error_response(status, message)
    ssl_socket.sendall(response)

# Dummy references to silence unused function warnings for linters and Pylance
_unused = (_extract_csr, _validate_csr_checksum)