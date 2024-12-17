from protocol import SSLConfig

from typing import Optional, Tuple
import tempfile
import logging
import signal
import ssl
import os


# Global variables 
running = True  # Declare the global

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def signal_handler(sig: int, frame) -> None:
    """Signal handler for SIGINT and SIGTERM."""

    global running
    logging.info("\nShutting down server...")
    running = False

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def cleanup(image_path: str) -> None:
    try:
        if os.path.exists(image_path):
            os.remove(image_path)
            logging.info(f"Cleaned up temporary file: {image_path}")
    except Exception as e:
        logging.error(f"Failed to cleanup temporary file: {e}")


def hide_key_in_image(image_data: bytes, large_shift: str) -> bytes:
    """Hide the encryption key in the image data."""

    try:
        if not isinstance(image_data, bytes):
            raise ValueError("Expected bytes for image_data")
            
        return image_data + f"KEY{{{large_shift}}}".encode('utf-8')
    except Exception as e:
        logging.error(f"Error in hide_key_in_image: {e}")
        raise


def extract_ssl_info(keylog_path: str = r"C:\my-CTF\pcap_creator\tls\logs\ssl_key_log.log") -> Tuple[str, str]:
   """
   Extract client random and master secret from SSL keylog content.
   Format: CLIENT_RANDOM <client_random_hex> <master_secret_hex>
   """
   try:
       with open(keylog_path, 'r') as f:
           content = f.read()

       parts = content.strip().split()
       if len(parts) == 3 and parts[0] == "CLIENT_RANDOM":
           return parts[1], parts[2]
           
       return None, None
       
   except Exception as e:
       print(f"Error reading keylog file: {e}")
       return None, None

def print_encryption_key() -> None:
    """Print the encryption key."""

    logging.info(f"Use the key: {SSLConfig.ENCRYPTION_KEY}")


def temp_cert_to_context(context: ssl.SSLContext, 
                        cert_file: str, 
                        key_file: Optional[str] = None) -> ssl.SSLContext:
    """Load temporary certificate and key files into SSL context."""
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
