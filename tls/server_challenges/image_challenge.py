"""
Image Challenge Module 
Implements functionality for embedding encryption keys in image data and encrypted messages
"""
import logging
import atexit
import os
import base64
from typing import Optional, List, Tuple, Final
from tls.protocol import SSLConfig
from tls.utils.image_data import EMBEDDED_IMAGE_DATA

IMAGE_PATH: Final[str] = "C:/Users/Public/Open-Me.png"

class ImageChallenge:
    """Handles image-based challenge operations and encrypted messages"""
    
    def __init__(self):
        self.image_path: str = IMAGE_PATH
        self.client_random, self.master_secret = self.extract_ssl_info()

        # Encrypted messages requiring Enigma config from image
        self.messages: List[str] = [
            "1. rteng eqmna jibjl kpvq",  # Mission Accomplished.
            "2. xasfh yynve watta epkas mtqot lhlyi rmmpb ifeuv ygsjl gqynv mxois jmjfh pgzle tposh gsoyb hoars lrmks qignd am",  # Key secured
            "3. xaswp wiqxw tpdih lflyc mykck clqyk sm",  # Legacy lives on
            "4. qjxfh nymcq {client_random} rhexp fjjns zp {master_secret}".format(
                client_random=self.client_random or "UNKNOWN",
                master_secret=self.master_secret or "UNKNOWN"
            )
        ]

        # Enigma configuration to hide in image
        self.enigma_config = (
            "{reflector} UKW B "
            "{ROTOR_POSITION_RING} VI A A I Q A III L A "
            "{PLUGBOARD} bq cr di ej kw mt os px uz gh"
        )

    def create_challenge_image(self) -> bool:
        """Create challenge image with embedded enigma configuration"""
        try:
            image_data = self.get_image_data()
            modified_data = self.hide_key_in_image(image_data, self.enigma_config)
            
            with open(self.image_path, 'wb') as f:
                f.write(modified_data)

            atexit.register(self.cleanup)
            return True
            
        except Exception as e:
            logging.error(f"Failed to create challenge image: {e}")
            return False

    def hide_key_in_image(self, image_data: bytes, key: str) -> bytes:
        """
        Embed the encryption key into the image data.

        Args:
            image_data (bytes): Original image data
            key (str): Encryption key to embed

        Returns:
            bytes: Modified image data with embedded key
        """
        try:
            key_bytes = key.encode()
            return image_data + key_bytes
        except Exception as e:
            logging.error(f"Failed to embed key in image: {e}")
            return image_data

    def get_encrypted_messages(self) -> List[str]:
        """Get the encrypted messages that require Enigma config from image"""
        return self.messages

    def cleanup(self) -> None:
        """Clean up temporary image file"""
        try:
            if os.path.exists(self.image_path):
                os.remove(self.image_path)
                logging.info(f"Cleaned up challenge image: {self.image_path}")
        except Exception as e:
            logging.error(f"Failed to cleanup challenge image: {e}")

    def extract_ssl_info(self, keylog_path: str = r"C:\my-CTF\pcap_creator\tls\logs\ssl_key_log.log") -> Tuple[Optional[str], Optional[str]]:
        """
        Extract SSL session information from keylog file.
        
        Args:
            keylog_path: Path to SSL keylog file
            
        Returns:
            Tuple containing client random and master secret values
        """
        try:
            with open(keylog_path, 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) == 3 and parts[0] == "CLIENT_RANDOM":
                        return parts[1], parts[2]
            return None, None
        except FileNotFoundError:
            logging.error(f"Keylog file not found: {keylog_path}")
            return None, None
        except Exception as e:
            logging.error(f"Error reading keylog file: {e}")
            return None, None

    def print_encryption_key(self) -> None:
        """Log the encryption key"""
        try:
            encryption_key = getattr(SSLConfig, "ENCRYPTION_KEY", None)
            if encryption_key:
                logging.info(f"Use the key: {encryption_key}")
            else:
                logging.warning("ENCRYPTION_KEY is not set in SSLConfig")
        except Exception as e:
            logging.error(f"Failed to retrieve ENCRYPTION_KEY: {e}")

    def get_image_data(self) -> bytes:
        """
        Returns the decoded image data.
        
        Returns:
            bytes: Decoded image data of Enigma machine
            
        Raises:
            ValueError: If decoding fails
        """
        try:
            return base64.b64decode(EMBEDDED_IMAGE_DATA)
        except Exception as e:
            raise ValueError(f"Failed to decode embedded image data: {e}")