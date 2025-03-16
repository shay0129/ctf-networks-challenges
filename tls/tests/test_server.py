"""Test module for main CTF server"""
import unittest
import pytest
from unittest.mock import Mock, patch
import socket
import ssl
import threading

from tls.server import CTFServer, create_server_ssl_context
from tls.protocol import ServerConfig

class TestCTFServer(unittest.TestCase):
    def setUp(self):
        """Set up test environment"""
        self.server = CTFServer()
        
    @pytest.mark.unit
    def test_server_initialization(self):
        """Test server initialization"""
        self.server.initialize()
        self.assertIsNotNone(self.server.context)
        self.assertIsNotNone(self.server.server_socket)
        
    @pytest.mark.unit
    def test_ssl_context_creation(self):
        """Test SSL context creation"""
        context = create_server_ssl_context(ServerConfig.CERT, ServerConfig.KEY)
        self.assertIsInstance(context, ssl.SSLContext)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        
    @pytest.mark.unit
    @patch('socket.socket')
    def test_client_connection_without_cert(self, mock_socket):
        """Test client connection rejection without certificate"""
        mock_client = Mock()
        mock_socket.accept.return_value = (mock_client, ('127.0.0.1', 12345))
        
        self.server.initialize()
        result = self.server.handle_client_request(mock_client, [])
        self.assertFalse(result)
        
    @pytest.mark.unit
    def test_challenge_progression(self):
        """Test challenge progression logic"""
        self.server.initialize()
        self.assertFalse(self.server.icmp_completed.is_set())
        
        # Simulate ICMP completion
        self.server.icmp_completed.set()
        self.assertTrue(self.server.icmp_completed.is_set())
        
    @pytest.mark.unit
    def test_message_encryption(self):
        """Test message encryption for challenges"""
        messages = self.server.image_challenge.get_encrypted_messages()
        self.assertIsInstance(messages, list)
        self.assertTrue(all(isinstance(m, str) for m in messages))
        
    @pytest.mark.unit
    @patch('socket.socket')
    def test_cleanup(self, mock_socket):
        """Test server cleanup"""
        self.server.initialize()
        self.server.cleanup()
        mock_socket.return_value.close.assert_called_once()