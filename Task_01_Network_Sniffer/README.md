# Task 01: Basic Network Sniffer

Developer: Cyber Jerry

## Overview
This script captures network packets in real time and parses Layer 3 and Layer 4 protocol headers including IP, IPv6, TCP, UDP, ICMP, and DNS.

## Features
- Real time packet capture using Scapy
- Displays source IP, destination IP, ports, TTL, and protocol flags
- Sanitizes raw packet payload into readable ASCII text
- Supports saving traffic into PCAP files for packet analysis

## How to Run

On Windows:
python Sniffer.py

On Linux:
sudo python3 Sniffer.py

Save traffic to a PCAP file:
python Sniffer.py -w output.pcap