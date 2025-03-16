"""Test module for image challenge"""
import unittest
import pytest
from unittest.mock import Mock, patch
import os
from pathlib import Path

from tls.server_challenges.image_challenge import ImageChallenge

class TestImageChallenge(unittest.TestCase):
    def setUp(self):
        """Set up test environment"""
        self.image = ImageChallenge()
        self.test_files = Path("tests/test_files/images")
        
    @pytest.mark.unit
    def test_encryption_key_embedding(self):
        """Test key embedding in image"""
        test_data = b"test_image_data"
        test_key = "test_encryption_key"
        result = self.image.hide_key_in_image(test_data, test_key)
        self.assertIn(test_key.encode(), result)
        
    @pytest.mark.unit
    def test_image_creation(self):
        """Test challenge image creation"""
        result = self.image.create_challenge_image()
        self.assertTrue(result)
        self.assertTrue(os.path.exists(self.image.image_path))
        
    @pytest.mark.unit
    def test_get_encrypted_messages(self):
        """Test retrieval of encrypted messages"""
        messages = self.image.get_encrypted_messages()
        self.assertIsInstance(messages, list)
        self.assertEqual(len(messages), 4)  # Should have 4 messages
        
    @pytest.mark.unit
    def test_ssl_info_extraction(self):
        """Test SSL session information extraction"""
        client_random, master_secret = self.image.extract_ssl_info()
        self.assertIsNotNone(client_random)
        self.assertIsNotNone(master_secret)
        
    @pytest.mark.unit
    def test_cleanup(self):
        """Test cleanup of temporary files"""
        self.image.create_challenge_image()
        self.assertTrue(os.path.exists(self.image.image_path))
        self.image.cleanup()
        self.assertFalse(os.path.exists(self.image.image_path))
        
    @pytest.mark.unit
    @patch('logging.info')
    def test_encryption_key_printing(self, mock_log):
        """Test encryption key logging"""
        self.image.print_encryption_key()
        mock_log.assert_called()