# type: ignore[attr-defined]
"""
ICMP Challenge Module
Handles ICMP-based challenges for the CTF server.
"""
import threading
import logging
import time
from typing import Any

from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sniff
from scapy.interfaces import dev_from_index  # Removed unused show_interfaces

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Special ID value used to identify packets from our client
CUSTOM_ICMP_ID = 0x1337

class ICMPChallenge:
    """ Handles ICMP-based challenge logic """

    def __init__(self):
        self.reset_state()
        self.completion_event = threading.Event()
        self.successful_pings: list[Any] = []
        self.start_time: float | None = None
    
    def handle_request(self, packet: Any) -> None:
        """ Processes incoming ICMP Echo Requests and validates the challenge sequence """
        if not packet.haslayer(ICMP) or not packet.haslayer(IP):
            return

        icmp_layer = packet.getlayer(ICMP)
        ip_layer = packet.getlayer(IP)

        # Check that this is a ping to the local machine
        if ip_layer.dst != "127.0.0.1":
            return
        
        # Check that this is an Echo Request packet
        if icmp_layer.type != 8:
            return
        
        # Check that the ID matches what our client sends
        if icmp_layer.id != CUSTOM_ICMP_ID:
            logging.debug(f"ID {icmp_layer.id} (expecting {CUSTOM_ICMP_ID})")
            return

        # Calculate the payload size
        payload_size = len(bytes(icmp_layer.payload)) if icmp_layer.payload else 0
        #logging.debug(f"Received ICMP packet from {ip_layer.src} with ID={icmp_layer.id}, seq={icmp_layer.seq}, size={payload_size} bytes")

        if len(self.successful_pings) >= 5:
            logging.info("Too many pings.")
            self.reset_state()
            return

        if not self.successful_pings:
            self.start_time = time.time()
            #logging.info("Challenge started. Expecting pings: 0, 100, 200, 300, 400 bytes")

        expected_size = len(self.successful_pings) * 100
        expected_seq = len(self.successful_pings) + 1

        # Check that the size and sequence are correct
        if payload_size != expected_size:
            logging.info(f"Incorrect ping size. Expected: {expected_size}, Got: {payload_size}")
            self.reset_state()
            return
        
        if icmp_layer.seq != expected_seq:
            logging.info(f"Incorrect ping sequence. Expected: {expected_seq}, Got: {icmp_layer.seq}")
            self.reset_state()
            return

        self.successful_pings.append(packet)
        logging.info(f"Valid ping #{len(self.successful_pings)} received with size {payload_size} bytes")

        if len(self.successful_pings) == 5:
            if self.start_time is not None:
                elapsed_time = time.time() - self.start_time
            else:
                elapsed_time = 0.0
            if 9 <= elapsed_time <= 11:
                logging.info(f"Challenge completed successfully in {elapsed_time:.2f} seconds.")
                self.completion_event.set()
            else:
                logging.info(f"Challenge failed. Took {elapsed_time:.2f} seconds (outside 9-11s). Resetting.")
                self.reset_state()
        else:
            logging.info(f"Waiting for next ping with size {len(self.successful_pings) * 100} bytes...")

    def reset_state(self) -> None:
        """ Resets the challenge state """
        self.start_time = None
        self.successful_pings = []
        #logging.debug("Challenge state reset.")

def start_icmp_server():
    """ Starts the ICMP listener and blocks until the challenge is truly completed. """
    # logging.info("Starting ICMP server...")
    # Select interface to listen on - choose the first interface
    interface = dev_from_index(1)  # Based on show_interfaces output
    
    # Display the selected interface
    # if interface:
    #     logging.info(f"Listening on interface: {interface}")
    # else:
    #     logging.info("Listening on all interfaces")

    print("bbHHh!") # Hint to the user to send a ping with this payload
    # Show available interfaces for reference
    challenge_handler = ICMPChallenge()
    bpf_filter = "icmp and host 127.0.0.1"
    try:
        while not challenge_handler.completion_event.is_set():
            sniff(
                filter=bpf_filter,
                prn=challenge_handler.handle_request,
                store=0,
                iface=interface,
                stop_filter=lambda p: challenge_handler.completion_event.is_set(),
                timeout=5  # Prevents infinite blocking if interface is broken
            ) # If sniffed 
        # logging.info("ICMP challenge event set. Proceeding.")
        return True
    except KeyboardInterrupt:
        # logging.info("Server stopped by user")
        pass
    except Exception as e:
        # logging.error(f"Error in sniffing: {e}")
        pass
    return False