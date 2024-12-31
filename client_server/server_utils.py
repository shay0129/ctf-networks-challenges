"""
Server Utilities Module
Provides SSL, encryption, and file handling utilities for the server.
"""
from protocol import SSLConfig
from typing import Optional, Tuple
import tempfile
import logging
import signal
import ssl
import os

# Global server state
running = True

def setup_logging() -> None:
    """Configure logging format and level."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def setup_signal_handlers() -> None:
    """Setup graceful shutdown handlers for SIGINT and SIGTERM."""
    def signal_handler(sig: int, frame) -> None:
        global running
        logging.info("\nShutting down server...")
        running = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

def cleanup(image_path: str) -> None:
    """
    Clean up temporary files.

    Args:
        image_path: Path to file that needs to be removed
    """
    try:
        if os.path.exists(image_path):
            os.remove(image_path)
            logging.info(f"Cleaned up temporary file: {image_path}")
    except Exception as e:
        logging.error(f"Failed to cleanup temporary file: {e}")

def hide_key_in_image(image_data: bytes, large_shift: str) -> bytes:
    """
    Embed encryption key in image data.

    Args:
        image_data: Original image bytes
        large_shift: Key data to hide

    Returns:
        Modified image data with embedded key

    Raises:
        ValueError: If image_data is not bytes
    """
    try:
        if not isinstance(image_data, bytes):
            raise ValueError("Expected bytes for image_data")
            
        return image_data + f"KEY{{{large_shift}}}".encode('utf-8')
    except Exception as e:
        logging.error(f"Error in hide_key_in_image: {e}")
        raise

def extract_ssl_info(keylog_path: str = r"C:\my-CTF\pcap_creator\tls\logs\ssl_key_log.log") -> Tuple[Optional[str], Optional[str]]:
    """
    Extract SSL session information from keylog file.

    Args:
        keylog_path: Path to SSL keylog file

    Returns:
        Tuple containing client random and master secret values, or (None, None) if extraction fails
    """
    try:
        with open(keylog_path, 'r') as f:
            content = f.read()

        parts = content.strip().split()
        if len(parts) == 3 and parts[0] == "CLIENT_RANDOM":
            return parts[1], parts[2]
           
        return None, None
       
    except Exception as e:
        logging.error(f"Error reading keylog file: {e}")
        return None, None

def print_encryption_key() -> None:
    """Log the encryption key."""
    logging.info(f"Use the key: {SSLConfig.ENCRYPTION_KEY}")

def temp_cert_to_context(context: ssl.SSLContext, 
                        cert_file: str, 
                        key_file: Optional[str] = None) -> ssl.SSLContext:
    """
    Load certificate and key into SSL context using temporary files.

    Args:
        context: SSL context to configure
        cert_file: Certificate content
        key_file: Private key content (optional)

    Returns:
        Configured SSL context
    """
    cert_path = None
    key_path = None
    
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_cert:
            temp_cert.write(cert_file)
            cert_path = temp_cert.name
        
        if key_file:
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_key:
                temp_key.write(key_file)
                key_path = temp_key.name
        
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        context.verify_flags = ssl.VERIFY_DEFAULT
        return context
        
    finally:
        # Clean up temp files
        if cert_path and os.path.exists(cert_path):
            os.unlink(cert_path)
        if key_path and os.path.exists(key_path):
            os.unlink(key_path)

# Initialize logging and signal handlers
setup_logging()
setup_signal_handlers()