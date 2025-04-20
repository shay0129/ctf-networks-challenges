"""Ping the server with custom ICMP packets using Scapy
This script sends ICMP Echo Request packets with incremental payload sizes to the server.
It uses Scapy to create and send the packets, and logs the responses received from the server.
The script is designed to work with a loopback interface (e.g., lo0) and can be run on various operating systems."""

from scapy.interfaces import show_interfaces, dev_from_index
from scapy.config import conf
from scapy.sendrecv import sr1
from scapy.layers.inet import IP, ICMP
import logging
import time

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Show available interfaces for reference
logging.info("Available interfaces:")
#show_interfaces()

# Define the interface to use for sending packets
conf.iface = dev_from_index(1)  # Replace the number with the index of the loopback interface

# Method 2: Select interface by name (works on most systems)
for iface_name, iface_data in conf.ifaces.items():
    if "lo" == iface_name or "Loopback" in str(iface_data):
        conf.iface = iface_name
        logging.info(f"Using interface: {conf.iface}")
        break
else:
    logging.error("Loopback interface not found. Please set it manually.")
    exit(1)

# Define the target IP address
target_ip = "127.0.0.1"

# Define a special ping type that the server can recognize
# We will use a special ID value
CUSTOM_ICMP_ID = 0x1337  # Unique value to identify our pings

def send_icmp_packets():
    """ Sends ICMP Echo Request packets with incremental payload sizes """
    sizes = [0, 100, 200, 300, 400]
    
    #logging.info(f"Using interface {conf.iface} for sending packets")
    
    for i, size in enumerate(sizes):
        data = b"A" * size
        
        # Create an ICMP packet with a special ID
        icmp_request = IP(dst=target_ip) / ICMP(id=CUSTOM_ICMP_ID, seq=i+1) / data
        
        logging.info(f"Sending ICMP packet #{i+1} with size {size} bytes to {target_ip}")
        
        # Use sr1 with verbose=0 to reduce output
        response = sr1(icmp_request, timeout=2, verbose=0, iface=conf.iface)
        
        if response:
            if response.haslayer(ICMP) and response.getlayer(ICMP).id == CUSTOM_ICMP_ID:
                logging.info(f"Received valid response from {response.src} for packet #{i+1}")
            else:
                logging.info(f"Received response from {response.src} but with different ID")
        else:
            logging.warning(f"No response received for packet #{i+1}")
        
        # To meet the server's timing requirements (9-11 seconds), wait a bit between packets
        if i < len(sizes) - 1:
            wait_time = 2.5  # About 2 seconds between each packet
            logging.info(f"Waiting {wait_time} seconds before next packet...")
            time.sleep(wait_time)

if __name__ == "__main__":
    send_icmp_packets()