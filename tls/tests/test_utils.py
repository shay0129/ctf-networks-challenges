"""Test module for utility functions"""
import unittest
import pytest
from unittest.mock import Mock, patch
import ssl
import socket
from pathlib import Path

from tls.utils.ca import (
    sign_csr_with_ca,
    verify_client_csr,
    validate_certificate,
    parse_http_request,
    read_http_request,
    format_error_response
)

class TestCertificateUtils(unittest.TestCase):
    def setUp(self):
        """Set up test environment"""
        self.test_files = Path("tests/test_files")
        
    @pytest.mark.unit
    def test_certificate_validation(self):
        """Test certificate validation"""
        with open(self.test_files / "certificates/valid/client.crt", "rb") as f:
            cert_data = f.read()
        self.assertTrue(validate_certificate(cert_data))
        
    @pytest.mark.unit
    def test_invalid_certificate_validation(self):
        """Test invalid certificate rejection"""
        self.assertFalse(validate_certificate(b"invalid cert"))
        
    @pytest.mark.unit
    def test_csr_signing(self):
        """Test CSR signing process"""
        with open(self.test_files / "valid/client.csr", "rb") as f:
            csr_data = f.read()
        with open(self.test_files / "ca/ca.key", "rb") as f:
            ca_key = f.read()
        with open(self.test_files / "ca/ca.crt", "rb") as f:
            ca_cert = f.read()
            
        result = sign_csr_with_ca(csr_data, ca_key, ca_cert)
        self.assertIsNotNone(result)

class TestHTTPUtils(unittest.TestCase):
    @pytest.mark.unit
    def test_http_request_parsing(self):
        """Test HTTP request parsing"""
        raw_request = (
            b"POST /sign HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Length: 5\r\n"
            b"\r\n"
            b"hello"
        )
        headers, body = parse_http_request(raw_request)
        self.assertEqual(headers[b'request_method'], b'POST')
        self.assertEqual(body, b'hello')
        
    @pytest.mark.unit
    def test_malformed_request_parsing(self):
        """Test handling of malformed requests"""
        raw_request = b"invalid request"
        result = parse_http_request(raw_request)
        self.assertIsNone(result)
        
    @pytest.mark.unit
    def test_error_response_formatting(self):
        """Test error response formatting"""
        response = format_error_response(
            b"HTTP/1.1 400 Bad Request",
            b"Error message"
        )
        self.assertIn(b"HTTP/1.1 400 Bad Request", response)
        self.assertIn(b"Error message", response)
        
class TestSocketUtils(unittest.TestCase):
    @pytest.mark.unit
    @patch('ssl.SSLSocket')
    def test_http_request_reading(self, mock_socket):
        """Test reading HTTP request from socket"""
        mock_socket.recv.return_value = (
            b"GET / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"\r\n"
        )
        result = read_http_request(mock_socket)
        self.assertIsNotNone(result)
