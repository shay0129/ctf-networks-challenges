"""
Test module for CA server functionality
"""
import unittest
import os
import ssl
from pathlib import Path
from unittest.mock import Mock, patch
import pytest

from tls.server_challenges.ca_challenge import CAChallenge
from tls.protocol import CAConfig

class TestCAServer(unittest.TestCase):
    """Test cases for CA server functionality"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        cls.test_dir = Path(__file__).parent
        cls.cert_dir = cls.test_dir / 'test_files' / 'certificates'
        
        # Load test certificates
        with open(cls.cert_dir / 'ca' / 'ca.crt', 'rb') as f:
            cls.ca_cert = f.read()
        with open(cls.cert_dir / 'ca' / 'ca.key', 'rb') as f:
            cls.ca_key = f.read()
            
    def setUp(self):
        """Initialize CA server for each test"""
        self.ca_server = CAChallenge()
        self.ca_server.cert_bytes = self.ca_cert
        self.ca_server.key_bytes = self.ca_key
        
    @pytest.mark.unit
    def test_unsigned_certificate(self):
        """Test rejection of certificate not signed by CA"""
        with open(self.cert_dir / 'invalid' / 'unsigned.crt', 'rb') as f:
            cert_data = f.read()
            
        # Create mock SSL socket
        mock_socket = self._create_mock_socket(cert_data)
        
        # Attempt to handle request with unsigned cert
        result = self.ca_server.handle_client_request(mock_socket)
        self.assertFalse(result)
        
        # Verify error response was sent
        mock_socket.sendall.assert_called_with(
            b'HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n' +
            b'Content-Length: 13\r\nConnection: close\r\n\r\nInvalid CSR\r\n'
        )
        
    @pytest.mark.unit
    def test_wrong_country_certificate(self):
        """Test rejection of certificate with wrong country code"""
        with open(self.cert_dir / 'invalid' / 'wrong_country.crt', 'rb') as f:
            cert_data = f.read()
            
        mock_socket = self._create_mock_socket(cert_data)
        result = self.ca_server.handle_client_request(mock_socket)
        self.assertFalse(result)
        
    @pytest.mark.unit
    def test_mitm_certificate(self):
        """Test detection of MITM certificate"""
        with open(self.cert_dir / 'invalid' / 'mitm.crt', 'rb') as f:
            cert_data = f.read()
            
        mock_socket = self._create_mock_socket(cert_data)
        result = self.ca_server.handle_client_request(mock_socket)
        self.assertFalse(result)
        
    @pytest.mark.unit
    def test_valid_certificate(self):
        """Test acceptance of valid certificate"""
        with open(self.cert_dir / 'valid' / 'client.crt', 'rb') as f:
            cert_data = f.read()
            
        mock_socket = self._create_mock_socket(cert_data)
        result = self.ca_server.handle_client_request(mock_socket)
        self.assertTrue(result)
        
    @pytest.mark.unit
    def test_valid_csr_signing(self):
        """Test successful signing of valid CSR"""
        with open(self.cert_dir / 'valid' / 'client.csr', 'rb') as f:
            csr_data = f.read()
            
        mock_socket = self._create_mock_socket(csr_data)
        result = self.ca_server.handle_client_request(mock_socket)
        self.assertTrue(result)
        
        # Verify signed certificate was sent
        self.assertTrue(mock_socket.sendall.called)
        response = mock_socket.sendall.call_args[0][0]
        self.assertIn(b'-----BEGIN CERTIFICATE-----', response)
        
    def _create_mock_socket(self, cert_data: bytes) -> Mock:
        """Create mock SSL socket with certificate data"""
        mock_socket = Mock()
        
        # Create HTTP request with certificate
        http_request = (
            b'POST /sign HTTP/1.1\r\n'
            b'Content-Type: application/x-pem-file\r\n'
            b'Content-Length: %d\r\n'
            b'\r\n'
            b'%s'
        ) % (len(cert_data), cert_data)
        
        # Configure mock to return request data
        mock_socket.recv.side_effect = [http_request]
        return mock_socket
        
if __name__ == '__main__':
    unittest.main()