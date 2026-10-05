# Live Packet Sniffer with Port Scan Detection

A Python-based live network sniffer built with Scapy. Captures packets on a
chosen interface, processes them through a producer-consumer queue, and
detects potential TCP port scanning activity using a rolling time window.

## Features

- Live packet capture using Scapy
- Producer-consumer pipeline using `Queue` and `threading`
- Extraction of source/destination IPs, ports, and protocols
- TCP SYN-based port scan detection
- Rolling 10-second time window with a configurable port threshold

## Requirements

- Python 3.x
- Scapy
- Root/sudo privileges (live packet capture requires elevated permissions)

Install dependencies:

    pip install -r requirements.txt

## Running

    sudo python sniffer.py

Note: Scapy's `sniff()` needs raw socket access, which requires root on most
systems.

## Detection Logic

The detector tracks unique destination ports contacted by each source IP
within a rolling 10-second window. If a source contacts 5 or more unique
destination ports in that window, it is flagged as a potential port scan.

Only TCP SYN packets are considered, since SYN represents a connection
attempt. Responses (SYN-ACK) are ignored to avoid counting the scanner's
own temporary source ports as scanned ports.

