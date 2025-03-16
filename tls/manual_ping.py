import socket
import struct
import time
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class IcmpPacketSender:
    def __init__(self, target_ip, data=None, ttl=64, icmp_id=12345):
        self.target_ip = target_ip
        self.data = data
        self.ttl = ttl
        self.icmp_id = icmp_id

    def send_icmp_packet(self):
        icmp_type = 8  # ICMP echo request
        icmp_code = 0
        icmp_checksum = 0
        icmp_sequence = 1

        # ICMP payload
        if self.data is not None:
            if isinstance(self.data, str):
                icmp_payload = self.data.encode()
            elif isinstance(self.data, int):
                # If data is a number, create payload of that size
                icmp_payload = b"A" * self.data
            else:
                icmp_payload = self.data
        else:
            icmp_payload = b""  # Empty payload by default

        # ICMP header
        icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, self.icmp_id, icmp_sequence)

        # Calculate checksum
        icmp_checksum = self.calculate_checksum(icmp_header + icmp_payload)

        # Update ICMP header with correct checksum
        icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, socket.htons(icmp_checksum), self.icmp_id, icmp_sequence)

        # Create ICMP packet
        icmp_packet = icmp_header + icmp_payload

        # Create raw socket
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            # Set socket TTL
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack("I", self.ttl))
            sock.settimeout(2)

            # Send packet
            try:
                sock.sendto(icmp_packet, (self.target_ip, 0))
                logging.info(f"ICMP packet sent to {self.target_ip} successfully! Size: {len(icmp_payload)} bytes")
            except socket.error as e:
                logging.error(f"Failed to send ICMP packet: {e}")

    def calculate_checksum(self, data):
        checksum = 0
        if len(data) % 2 != 0:
            data += b"\x00"
        for i in range(0, len(data), 2):
            checksum += (data[i] << 8) + data[i+1]
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum += checksum >> 16
        return (~checksum) & 0xffff

def send_challenge_sequence():
    """Sends the required sequence of pings for the challenge"""
    sizes = [0, 100, 200, 300, 400]
    target_ip = "127.0.0.1"
    logging.info("Starting challenge sequence...")
    
    for size in sizes:
        sender = IcmpPacketSender(target_ip, data=size)
        sender.send_icmp_packet()
        time.sleep(2)  # Wait 2 seconds between pings
        
    logging.info("Challenge sequence completed!")

if __name__ == "__main__":
    choice = input("Choose mode:\n1. Single ping\n2. Challenge sequence\nEnter choice (1/2): ")
    
    if choice == "1":
        target_ip = input("Enter target IP: ")
        size = input("Enter payload size (optional, press Enter for empty): ")
        ttl = input("Enter TTL (optional, press Enter for default): ")
        
        sender = IcmpPacketSender(
            target_ip,
            data=int(size) if size else None,
            ttl=int(ttl) if ttl else 64
        )
        sender.send_icmp_packet()
    
    elif choice == "2":
        send_challenge_sequence()
    
    else:
        print("Invalid choice!")