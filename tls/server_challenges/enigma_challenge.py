"""
Enigma Challenge
This module creates an image with embedded Enigma configuration and audio data.
It also provides methods to extract the configuration and messages from the image.
"""
from typing import Final, List
import logging
import os

import base64

from ..utils.image_data import EMBEDDED_IMAGE_DATA
from ..utils.audio_data import EMBEDDED_AUDIO_DATA_b64

IMAGE_PATH: Final[str] = "C:/Users/Public/Open-Me.png"
SEPARATOR: Final[bytes] = b"-----ENIGMA_CONFIG_START-----"
SEPARATOR_END: Final[bytes] = b"-----ENIGMA_CONFIG_END-----"

class EnigmaChallenge:
    def __init__(self):
        self.image_path: str = IMAGE_PATH
        self.enigma_config: str = (
            "{reflector} UKW B "
            "{ROTOR_POSITION_RING} VI A A I Q A III L A "
            "{PLUGBOARD} bq cr di ej kw mt os px uz gh"
        )
        self.audio_base64: str = EMBEDDED_AUDIO_DATA_b64
        self.messages: List[str] = [
            "xasnf faybk latqe ku 64", # The string is on base 64
            "evshx zxjqs qpdhw?" # Are you heard that?
        ]

    def create_challenge_image(self) -> bool:
        try:
            image_data = self.get_image_data()
            enigma_config_bytes = self.enigma_config.encode('utf-8') # use the bytes of the config
            encoded_audio_bytes = self.audio_base64.encode('utf-8') # use the bytes of the audio

            modified_data = (
                image_data +
                SEPARATOR +
                enigma_config_bytes +
                SEPARATOR_END +
                encoded_audio_bytes
            )

            with open(self.image_path, 'wb') as f:
                f.write(modified_data)
            return True
        except Exception as e:
            logging.error(f"Failed to create challenge image: {e}")
            return False

    def get_image_data(self) -> bytes:
        try:
            return base64.b64decode(EMBEDDED_IMAGE_DATA)
        except Exception as e:
            raise ValueError(f"Failed to decode embedded image data: {e}")

    def get_encrypted_messages(self) -> List[str]:
        """Get the encrypted messages that require Enigma config from image"""
        return self.messages

    def get_image_path(self) -> str:
        """Get the path to the image"""
        return self.image_path
    
    def cleanup(self) -> None:
        """Clean up temporary image file"""
        try:
            if os.path.exists(self.image_path):
                os.remove(self.image_path)
                logging.info(f"Cleaned up challenge image: {self.image_path}")
        except Exception as e:
            logging.error(f"Failed to cleanup challenge image: {e}")
    def hide_key_in_image(self, image_data: bytes, enigma_add: str) -> bytes:
        """Hide the Enigma config in the image data"""
        try:
            enigma_config_bytes = enigma_add.encode('utf-8')
            modified_data = (
                image_data +
                SEPARATOR +
                enigma_config_bytes +
                SEPARATOR_END
            )
            return modified_data
        except Exception as e:
            logging.error(f"Failed to hide key in image: {e}")
            raise