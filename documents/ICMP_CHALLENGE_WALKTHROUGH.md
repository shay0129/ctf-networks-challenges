# Phase 1: ICMP Challenge Walkthrough

## Overview

This phase covers the covert channel ICMP challenge, requiring packet crafting, timing, and protocol analysis. Participants must craft a precise sequence of ICMP packets to a local server, using custom fields and timing constraints.

## Prerequisites
- Basic knowledge of ICMP protocol
- Familiarity with Scapy or raw socket programming in Python
- Ability to analyze network traffic (Wireshark recommended)

## Step-by-Step Solution

1. **Understand the Challenge Requirements**
   - The server expects 5 ICMP Echo Request packets to 127.0.0.1.
   - Each packet must have a custom ICMP ID: `0x1337` (4919 in decimal).
   - The payload size must increase by 100 bytes each time: 0, 100, 200, 300, 400 bytes.
   - The sequence number must increment from 1 to 5.
   - The entire sequence must be completed within 9-11 seconds.

2. **Crafting the Packets (Scapy Example)**
```python
from scapy.all import IP, ICMP, send
import time
sizes = [0, 100, 200, 300, 400]
for i, size in enumerate(sizes):
    data = b"A" * size
    pkt = IP(dst="127.0.0.1") / ICMP(id=0x1337, seq=i+1) / data
    send(pkt)
    time.sleep(2)  # 2 seconds between packets for correct timing
```

3. **Hints & Discovery**
   - The server may display a cryptic message like `bbHhh!` (struct format hint).
   - Use Wireshark to inspect ICMP traffic and confirm packet structure.
   - If packets are not accepted, check the ICMP ID and payload size.

4. **Validation**
   - If successful, the server will signal completion and allow you to proceed to the next phase.

## Troubleshooting
- **Packets not accepted?**
  - Double-check the ICMP ID (`0x1337`), sequence numbers, and payload sizes.
  - Ensure the timing is within the 9-11 second window.
- **Tools**: Use Scapy for packet crafting, Wireshark for traffic analysis.

## Reference Implementation
See `tls/server_challenges/ping_player.py` for a working example.
