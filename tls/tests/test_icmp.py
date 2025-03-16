"""Test module for ICMP challenge"""
import unittest
import pytest
from unittest.mock import Mock, patch
import time
from scapy.layers.inet import IP, ICMP, Raw

from tls.server_challenges.icmp_challenge import ICMPChallenge

class TestICMPChallenge(unittest.TestCase):
    def setUp(self):
        """Set up test environment"""
        self.icmp = ICMPChallenge()
        
    def create_mock_packet(self, payload_size=0):
        """Create mock ICMP packet"""
        mock_packet = Mock()
        mock_packet.haslayer.return_value = True
        mock_packet[ICMP].type = 8
        mock_packet[Raw].load = b'A' * payload_size
        mock_packet[IP].src = '127.0.0.1'
        return mock_packet

    @pytest.mark.unit
    def test_timing_validation_too_fast(self):
        """Test rejection of too fast requests"""
        self.icmp.first_ping_time = time.time() - 5  # Too fast
        packet = self.create_mock_packet()
        self.assertFalse(self.icmp._validate_request(packet))
        
    @pytest.mark.unit
    def test_timing_validation_too_slow(self):
        """Test rejection of too slow requests"""
        self.icmp.first_ping_time = time.time() - 15  # Too slow
        packet = self.create_mock_packet()
        self.assertFalse(self.icmp._validate_request(packet))
        
    @pytest.mark.unit
    def test_payload_size_progression(self):
        """Test payload size validation"""
        self.icmp.first_ping_time = time.time() - 10  # Correct timing
        
        # Test each request in sequence
        for i in range(5):
            self.icmp.request_count = i + 1
            packet = self.create_mock_packet(i * 100)
            self.assertTrue(self.icmp._validate_request(packet))
            
    @pytest.mark.unit
    def test_too_many_requests(self):
        """Test rejection of too many requests"""
        self.icmp.request_count = 6
        packet = self.create_mock_packet()
        self.assertFalse(self.icmp._validate_request(packet))
        
    @pytest.mark.unit
    def test_wrong_payload_size(self):
        """Test rejection of wrong payload size"""
        self.icmp.first_ping_time = time.time() - 10
        self.icmp.request_count = 2
        packet = self.create_mock_packet(150)  # Should be 100
        self.assertFalse(self.icmp._validate_request(packet))
        
    @pytest.mark.unit
    def test_completion_event(self):
        """Test completion event triggering"""
        mock_event = Mock()
        self.icmp.set_completion_event(mock_event)
        
        # Simulate successful completion
        self.icmp.first_ping_time = time.time() - 10
        for i in range(5):
            self.icmp.request_count = i + 1
            packet = self.create_mock_packet(i * 100)
            self.icmp.handle_request(packet)
            
        mock_event.set.assert_called_once()